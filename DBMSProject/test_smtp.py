import smtplib

try:
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()  # Enable TLS
    server.login('meghanaaithal1863@gmail.com', 'dgqb fvti raic qnco')
    print("Connection successful")
except Exception as e:
    print(f"Failed to connect: {e}")
finally:
    server.quit()
