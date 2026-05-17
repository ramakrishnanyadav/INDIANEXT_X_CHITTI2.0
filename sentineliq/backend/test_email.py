import asyncio
from fastapi.testclient import TestClient
from main import app  # Assuming main.py exports app
import json

client = TestClient(app)

def run_test(name, vector):
    print(f"\n{'='*40}")
    print(f"Running Test: {name}")
    print(f"{'='*40}")
    
    response = client.post(
        "/api/v1/analyze",
        data={
            "threat_type": "email",
            "content": json.dumps(vector)
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"Verdict: {data.get('verdict')}")
        print(f"Confidence: {data.get('confidence')}")
        print("Feature Attribution Scores:")
        for feat in data.get("shap_features", []):
            print(f"  - {feat['feature']}: {feat['weight']}")
    else:
        print(f"Error: {response.text}")

def test_all():
    # Case 1: Extreme Max Vector
    run_test("1. Extreme Vector (Theoretical Max)", {
        "urgency_score": 1.0,
        "sender_mismatch": True,
        "attachment_risk": 1.0,
        "homoglyph_detected": True,
        "link_count_anomaly": 1.0,
        "suspicious_links": 1.0
    })
    
    # Case 2: Realistic Noisy Vector
    run_test("2. Realistic Noisy Phishing", {
        "urgency_score": 0.6,
        "sender_mismatch": True,
        "attachment_risk": 0.0,
        "homoglyph_detected": False,
        "link_count_anomaly": 0.0,
        "suspicious_links": 0.8
    })

    # Case 3: Low Signal Vector (Should be BENIGN or low SUSPICIOUS)
    run_test("3. Low Signal Vector", {
        "urgency_score": 0.2,
        "sender_mismatch": False,
        "attachment_risk": 0.0,
        "homoglyph_detected": False,
        "link_count_anomaly": 1.0,  # Just lots of links (e.g. newsletter)
        "suspicious_links": 0.0
    })

if __name__ == "__main__":
    test_all()
