import qrcode

url = "http://10.115.241.44:5000/advisory"

img = qrcode.make(url)
img.save("advisory_qr.png")

print("QR Code generated successfully: advisory_qr.png")