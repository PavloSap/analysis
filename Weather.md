import requests

API_KEY = "your_api_key"
CITY = input("Enter city: ")

url = f"http://api.openweathermap.org/data/2.5/weather?q={CITY}&appid={API_KEY}&units=metric"
response = requests.get(url)
data = response.json()

if data["cod"] == 200:
    print(f"Weather in {CITY}: {data['weather'][0]['description']}")
    print(f"Temperature: {data['main']['temp']}°C")
else:
    print("City not found!")
