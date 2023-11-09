from tkinter import *
from PIL import ImageTk, Image
import requests
import json



root = Tk()
root.title('API testing')
root.geometry("400x100")
root.configure(background="green")

try:
    api_request = requests.get("https://www.airnowapi.org/aq/observation/zipCode/current/?format=application/json&zipCode=20002&distance=5&API_KEY=1C6849D8-7C75-4ABC-B35D-871877D81419")
    api = json.loads(api_request.content)
    city = api[0]['ReportingArea']
    quality = api[0]['AQI']
    category = api[0]['Category']['Name']

    # if category == "Good"

    mylabel = Label(root, text="City \t\t: " + city + "\nAir Quality \t: " + str(quality) + "\nCategory \t\t: " + category,font=('Arial',14),background="green",justify='left')
    mylabel.pack()
except Exception as e:
    api = "Error"



# mylabel = Label(root, text=api[0]['AQI'])
# mylabel.pack()
# mylabel = Label(root, text=api[0]['Category']['Name'])
# mylabel.pack()

root.mainloop()