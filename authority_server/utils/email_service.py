import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

voting_url = os.getenv("VOTING_SERVER_URL", "192.168.1.55")
def get_smtp_connection():
    """creates and return connection using data from .env."""
    sender_email = os.getenv("MAIL_USERNAME")
    sender_password = os.getenv("MAIL_PASSWORD")
    if not sender_email or not sender_password:
        raise ValueError("Sender email and password are required and cannot be empty/None")
    
    server_addr = os.getenv('SMTP_ADDRESS', 'smtp.seznam.cz')
    port = int(os.getenv('SMTP_PORT', '465'))
    
    server = smtplib.SMTP_SSL(server_addr, port)
    server.login(sender_email, sender_password)
    return server, sender_email

def send_admin_email(creator_email, poll_title, poll_id, admin_password):
    """Sends the creator password for access to administration on the Voting server"""
    try:
        server, sender_email = get_smtp_connection()
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = creator_email
        msg['Subject'] = f"Administration access to: {poll_title}"
        
        admin_link = f"{voting_url}/admin?poll_id={poll_id}"
        
        body = f"""Dear user,
        
You have successfully created the poll: "{poll_title}".

IMPORTANT: Keep this email safe. You can use the link below to access the admin menu. In the menu, you can manage the poll or end it early.

Link to admin login: {admin_link}
Your poll ID: {poll_id}
Your admin password: {admin_password}

Regards,
Voting Authority System
"""
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send voter email to {creator_email}: {e}")
        return False
    
def send_voter_email(voter_email, poll_title, magic_link):
    """Sends the unique voting link to a registered voter."""
    try:
        server, sender_email = get_smtp_connection()
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = voter_email
        msg['Subject'] = f"Invitation to vote: {poll_title}"
        
        body = f"""Dear voter,
        
You have been invited to vote in the poll: "{poll_title}".

Click the secure link below to cast your vote:
{magic_link}

WARNING: This is your personal voting link. Do not share it with anyone, or they will be able to vote on your behalf.

Regards,
Voting Authority System
"""
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send voter email to {voter_email}: {e}")
        return False