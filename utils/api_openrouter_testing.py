"""
Connection test to OpenRouter (DeepSeek V4 Flash Free) using the API key from the .env file
"""

import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

API_KEY = os.getenv("deepseek_api_key")
MODEL = "deepseek/deepseek-v4-flash:free"
SITE_URL = ""
APP_NAME = ""


def test_openrouter():
    if not API_KEY:
        print("❌ ERROR: deepseek_api_key not found in the .env file")
        return False


    print(f"🔑 Using key: {API_KEY[:8]}...")
    print(f"🤖 Model: {MODEL}")
    print("📡 Sending request to OpenRouter...")


    try:
        
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",   # OpenRouter endpoint
            api_key=API_KEY,                           
            default_headers={
                "HTTP-Referer": SITE_URL,
                "X-Title": APP_NAME,
            }
        )


        completion = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Reply with one word only: OK"}
            ],
            max_tokens=10,
            temperature=0.0,
        )


        answer = completion.choices[0].message.content.strip()
        print(f"✅ Model response: {answer}")
        if answer.lower() == "ok":
            print("🎉 Test successful! The API key works correctly.")
            return True
        else:
            print("⚠️ Unexpected response, but the connection was successful.")
            return True


    except Exception as e:
        print(f"❌ ERROR during API call: {e}")
        return False


if __name__ == "__main__":
    success = test_openrouter()
    exit(0 if success else 1)