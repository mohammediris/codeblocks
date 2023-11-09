import smtplib
from email import encoders 
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart

email = 'alerts@schoolofiris.com'
smtp_server = 'smtp.dreamhost.com'
to_email = 'schoolofiris@gmail.com'
subject = 'this is 5th email'
message_file = 'mailclientmsg.txt'
password_file = 'password.txt'

# server = smtplib.SMTP('smtp.dreamhost.com',25) # for mail clients without SSL/TLS
server = smtplib.SMTP_SSL(smtp_server,465)
server.ehlo()
with open(password_file,'r') as p:
    passwd = p.read()
print(passwd)
server.login(email,passwd)

msg = MIMEMultipart()
msg['From'] = email
msg['To'] = to_email
msg['Subject'] = subject

with open (message_file,'r') as f:
    message = f.read()
print(message)
msg.attach(MIMEText(message,'plain'))

"""following code is for attaching any image file with the mail"""
filename = 'coding.png'
attachement = open(filename,'rb')
p = MIMEBase('application','octect-stream')
p.set_payload(attachement.read())
encoders.encode_base64(p)
p.add_header('Content-Disposition',f'attachment;filename = {filename}')
msg.attach(p)

text = msg.as_string() # here we combine all the parts of messages into one string

server.sendmail(email,to_email,text)