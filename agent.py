import json
import anthropic

client = anthropic.Anthropic()

# ---- Simulated back-ends (stand-ins for real threat intel + CMDB) ----
IP_REPUTATION = {
    "203.0.113.47": "MALICIOUS - known brute-force source, seen in 3 prior incidents",
    "45.132.104.9": "MALICIOUS - flagged for data-exfil C2 infrastructure",
    "82.14.201.22": "CLEAN - ACME corporate egress range",
}
ASSETS = {
    "prod-db-01": "Criticality: HIGH. Production customer DB. Owner: Data Platform team.",
    "workstation-4417": "Criticality: MEDIUM. Finance endpoint. Owner: J. Okafor.",
}

# ---- Tool implementations: plain Python functions ----
def lookup_ip_reputation(ip):
    return IP_REPUTATION.get(ip, f"UNKNOWN - no reputation data for {ip}")

def lookup_asset(hostname):
    return ASSETS.get(hostname, f"UNKNOWN - no asset record for {hostname}")

def write_case_file(filename, content):
    with open(filename, "w") as f:
        f.write(content)
    return f"Case file written to {filename} ({len(content)} chars)"

# Map tool name -> the function that runs it
TOOL_FUNCTIONS = {
    "lookup_ip_reputation": lookup_ip_reputation,
    "lookup_asset": lookup_asset,
    "write_case_file": write_case_file,
}

# ---- Tool schemas: what the model is allowed to call ----
TOOLS = [
    {
        "name": "lookup_ip_reputation",
        "description": "Look up threat-intel reputation for an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
    {
        "name": "lookup_asset",
        "description": "Look up asset criticality and owner for a hostname.",
        "input_schema": {
            "type": "object",
            "properties": {"hostname": {"type": "string"}},
            "required": ["hostname"],
        },
    },
    {
        "name": "write_case_file",
        "description": "Write the final investigation case file to disk.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["filename", "content"],
        },
    },
]

SYSTEM_PROMPT = """You are an autonomous SOC investigation agent for ACME Steel.
Given an alert, investigate it using the tools available:
- look up the reputation of any suspicious IP,
- look up the criticality of any affected asset,
then write a concise case file with your findings and a verdict
(BENIGN / SUSPICIOUS / ESCALATE) using write_case_file.
Work step by step. Once the case file is written, stop."""


def run_agent(task, max_turns=10):
    # (1) STATE lives here: the whole conversation, and it GROWS every turn.
    messages = [{"role": "user", "content": task}]

    for turn in range(1, max_turns + 1):
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        # Record what the model did this turn (into the growing state).
        messages.append({"role": "assistant", "content": response.content})

        # Show any reasoning text the model emitted.
        for block in response.content:
            if block.type == "text":
                print(f"[turn {turn}] think: {block.text.strip()}")

        # (2) STOP CONDITION: if it didn't call a tool, it's finished.
        if response.stop_reason != "tool_use":
            print(f"[turn {turn}] DONE.")
            return

        # (3) THE LOOP BODY: run each tool call, collect the results.
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                fn = TOOL_FUNCTIONS[block.name]
                print(f"[turn {turn}] call: {block.name}({json.dumps(block.input)})")
                result = fn(**block.input)
                print(f"[turn {turn}]   -> {result}")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })

        # Feed results back in as the next turn. THIS closes the loop.
        messages.append({"role": "user", "content": tool_results})

    print(f"Hit max_turns ({max_turns}) without finishing.")


if __name__ == "__main__":
    alert = """Rule: Multiple failed SSH logins followed by success
Source IP: 203.0.113.47
Destination host: prod-db-01
47 failed attempts in 90s, then successful auth as 'svc_backup'
Time: 2026-07-27 02:14 UTC"""
    run_agent(alert)
