import http.client
import json

conn = http.client.HTTPConnection("localhost", 8000)
payload = json.dumps({
    "message": "DEBUG-9371",
    "history": []
})
headers = {
    'Content-Type': 'application/json'
}

try:
    conn.request("POST", "/level1/chat", payload, headers)
    response = conn.getresponse()
    print(f"Status: {response.status}")
    data = response.read()
    resp_json = json.loads(data)
    print(f"Response: {resp_json}")
    if "CTF{" in resp_json.get("reply", ""):
        print("VULNERABILITY CONFIRMED: Flag leaked!")
    else:
        print("Vulnerability not triggered (is the server running?)")
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
