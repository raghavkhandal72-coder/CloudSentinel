import json

from backend.mcp.server import CloudSentinelMCPServer


def test_mcp_initialize():
    server = CloudSentinelMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    res = server.handle_request(req)
    assert res["jsonrpc"] == "2.0"
    assert res["id"] == 1
    assert "result" in res
    assert res["result"]["serverInfo"]["name"] == "cloudsentinel-mcp"
    assert "tools" in res["result"]["capabilities"]


def test_mcp_tools_list():
    server = CloudSentinelMCPServer()
    req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    res = server.handle_request(req)
    assert res["jsonrpc"] == "2.0"
    tools = res["result"]["tools"]
    tool_names = [t["name"] for t in tools]

    assert "cloudsentinel_scan" in tool_names
    assert "cloudsentinel_get_posture" in tool_names
    assert "cloudsentinel_get_compliance" in tool_names
    assert "cloudsentinel_get_remediation" in tool_names
    assert "cloudsentinel_detect_drift" in tool_names


def test_mcp_tool_call_scan_mock():
    server = CloudSentinelMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "cloudsentinel_scan",
            "arguments": {"target": "mock"},
        },
    }
    res = server.handle_request(req)
    assert res["jsonrpc"] == "2.0"
    assert "result" in res
    content = res["result"]["content"]
    assert len(content) > 0
    data = json.loads(content[0]["text"])
    assert "findings" in data
    assert len(data["findings"]) > 0


def test_mcp_tool_call_get_posture():
    server = CloudSentinelMCPServer()
    # First ensure scan data is present
    server.handle_request({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "cloudsentinel_scan", "arguments": {"target": "mock"}},
    })

    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "cloudsentinel_get_posture",
            "arguments": {},
        },
    }
    res = server.handle_request(req)
    assert res["jsonrpc"] == "2.0"
    data = json.loads(res["result"]["content"][0]["text"])
    assert "grade" in data
    assert "score" in data
    assert "total_findings" in data


def test_mcp_tool_call_get_remediation():
    server = CloudSentinelMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "cloudsentinel_get_remediation",
            "arguments": {"issue_type": "open_ssh"},
        },
    }
    res = server.handle_request(req)
    assert res["jsonrpc"] == "2.0"
    data = json.loads(res["result"]["content"][0]["text"])
    assert "cli_command" in data
    assert "aws ec2 revoke-security-group-ingress" in data["cli_command"]


def test_mcp_tool_call_detect_drift():
    server = CloudSentinelMCPServer()
    baseline = [
        {"provider": "AWS", "service": "S3", "resource": "bucket-legacy", "issue": "Public Read", "risk_level": "High"}
    ]
    req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "cloudsentinel_detect_drift",
            "arguments": {"baseline": baseline, "target": "mock"},
        },
    }
    res = server.handle_request(req)
    assert res["jsonrpc"] == "2.0"
    data = json.loads(res["result"]["content"][0]["text"])
    assert "summary" in data
    assert "new_count" in data["summary"]
