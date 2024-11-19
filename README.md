# **Secure TCP messanger**

A Python-based TCP messenger with a focus on security. Chat with your friends about top-secret Fortnite strategies.

---

## Features

- **End-to-End Encryption**: Messages are encrypted with AES algorithm. 
- **Dynamic Keys**: Each session a new AES key is generated.
- **Secure Key Exchange**: RSA encryption is used to securely exchange AES keys between clients.
- **SSL Secured Server**: All packets between the server and clients are encrypted with SSL.
- **Stateless Server**: No database is used for storing messages, ensuring minimal data exposure.

---

## How it Works

1. **Server**: 
   - Run the server on a machine with port forwarding to make it accessible publicly.
   - The server only broadcasts encrypted messages and does not decrypt them.

2. **Admin**: 
   - Responsible for creating an AES key for each session.
   - Uses RSA to securely send the AES key to other clients.
   - Sends and receives encrypted messages.

3. **Client**:
   - Connects to the server and receives the AES key for secure communication.
   - Sends and receives encrypted messages.


## Files in the Repository

1. **`server.py`**  
   The server application that broadcasts encrypted messages between clients.  
   > **Note**: This requires port forwarding for public access (otherwise server will    work only in Local Area Network).

2. **`admin.py`**  
   The admin application for generating unique AES keys for each session.

3. **`client.py`**  
   The client application for connecting to the server and retrieving AES keys.

---

## Installation and Usage

### Prerequisites
- Python 3.8 or later.
- `pycryptodome` and `cryptography` for encryption:  
  ```bash
  pip install pycryptodome
  pip install cryptography
  ```
- `customtkinter` for UI:
  ```bash
  pip install customtkinter
  ```

### Step-by-Step guide
1. **Server setup**
> Note: For server public access enable Port Forwarding on your router.
- Open `server.py` file and change the `port` variable to assigned port.
- Create a self-signed SSL certificate.
- Extract the server SSL certificate public key (copy and save it in the secure-stored file)
- Run the `server.py` on your machine that will act as a server:
```bash
python server.py
```
2. **Admin and Client setup**
- Check **Prerequisites** tab and install necessary libraries 
- Open `admin.py`/`client.py` file and change the `serv_key` variable to server SSL certificate public key.
- Change `hostname`, `server_ip` and `server_port` variables to server SSL hostname, public IP address and port.
- Run the `admin.py`/`client.py`
```bash
python admin.py
```
- Enter server credentials (public IP address and port) and click on `Connect` button.
- Wait until another user will connect (server message will pop-up)

---

## Future Updates
Planning to add:
- Improved UI
- Multiple server choice
- Storing server credentials
- User authentication, with login data stored securely in a JSON file on the server
- Support for group chats (more than two users in a session)
- Friend list management and tabbed chat interfaces
- New version with AWS support
