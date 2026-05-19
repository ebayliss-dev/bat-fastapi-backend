import os
import vonage


def send_magic_link_sms(phone: str, link: str):

# if you want to manage your secret, please do so by visiting your API Settings page in your dashboard
    client = vonage.Client(key="fb59843d", secret="VUjJWeQiA0fVbZq)j)NzZ2P")
    sms = vonage.Sms(client)

    message = link

    response = sms.send_message(
        {
            "from": "BAT",
            "to": phone,
            "text": message,
        }
    )

    if response["messages"][0]["status"] != "0":
        raise Exception(response["messages"][0].get("error-text"))