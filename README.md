# Mission-Impixellable
# MISSION IMPIXELLABLE: Hybrid Cryptography and Steganography

**Course:** UE25CS151A – PCPS Jackfruit Problem  
**Department:** Computer Science and Engineering, PES University  
**Semester:** 1

---

## 👥 Team Members

| Name | SRN |
| :--- | :--- |
| **Bhuvan V.** | PES2UG25EC035 |
| **G. P. Pranav Vittal** | PES2UG25CS182 |

**Under the guidance of:** Prof. Ankita Singhai

---

## 📝 Problem Statement
In modern digital communication, the need for both secure (encrypted) and covert (hidden) data transfer is paramount. Traditional encryption methods make the presence of a secret message obvious, potentially attracting unwanted attention, while simple steganography methods (like LSB) are vulnerable if the mechanism is known.

The objective of this project is to develop a tool that combines the security of **Hybrid Encryption** (RSA for key exchange, AES-GCM for data encryption) with the covertness of **Least Significant Bit (LSB) Steganography**.

---

## ⚙️ Approach & Methodology
This project implements a **Hybrid Cryptography Steganography System** using a modular, object-oriented approach in Python, integrated with a Tkinter GUI.

### The Process
1.  **Hybrid Encryption:**
    * **Data Layer:** The secret message is encrypted using **AES-GCM (256-bit)**.
    * **Key Layer:** The 32-byte AES key is encrypted using **RSA (2048-bit)** with OAEP padding, utilizing the recipient's public key.
2.  **Payload Packing:** The encrypted components (RSA-wrapped Key, AES Nonce, AES Tag, and Ciphertext) are packed into a single binary payload using the `struct` module.
3.  **Steganography (LSB):** This binary payload is embedded into the Least Significant Bit (LSB) of the RGB color channels of a **PNG cover image**, making the modification visually imperceptible.
4.  **Decryption:** The reverse process extracts the payload, unwraps the keys using the recipient's Private RSA key, and decrypts the message.

---

## 💻 Installation & Usage

### Prerequisites
* Python 3.x
* Required Libraries:
    ```bash
    pip install pillow cryptography
    ```

### How to Run
1.  Clone the repository.
2.  Run the main script:
    ```bash
    python working.py
    ```

### Execution Flow & Screenshots

#### 1. Main Interface
The application opens with a simple choice to either Encode or Decode data.

![Main Menu](Screenshot%20(1785).png)

#### 2. Encoding Phase (Hiding Data)
* **Input:** Select the Cover Image (`Photo.jpg`), enter the secret message, and select the Recipient's Public Key.
* **Action:** Click "Encode" to generate the Stego Image.

![Encoding Input](Screenshot%20(1787).png)

* **Result:** A success message confirms the data is hidden.

![Success Message](Screenshot%20(1788).png)

#### 3. Decoding Phase (Retrieving Data)
* **Input:** Select the generated Stego Image (`output.jpg`) and the Recipient's Private Key.

![Decoding Input](Screenshot%20(1789).png)

* **Output:** The decrypted message is revealed in a pop-up window, matching the original input exactly.

![Decoded Output](Screenshot%20(1791).png)

---

## 📸 Sample Input/Output Files

Below is a comparison of the original cover image and the resulting stego image. Despite containing the encrypted secret message, the images appear identical to the human eye.

| Type | File | Visual |
| :--- | :--- | :--- |
| **Input (Cover)** | `Photo.jpg` | ![Cover Image](Photo.jpg) |
| **Output (Stego)** | `output.png` | ![Stego Image](output.png) |

---

## 🚧 Challenges Faced
* **Bitstream Alignment:** Ensuring the exact length of the payload (key, nonce, tag, ciphertext) is correctly calculated so that LSB insertion starts and stops precisely.
* **Error Handling (GUI):** Implementing robust exception handling for file I/O errors and cryptographic mismatches (e.g., using the wrong private key).
* **Capacity Limitation:** Ensuring the user is warned if the secret message size exceeds the LSB capacity of the chosen cover image.

---

## 🚀 Scope for Improvement
* **Alternative Algorithms:** Integrating Discrete Cosine Transform (DCT) or DWT to improve robustness against statistical attacks.
* **Key Security:** Adding password protection to the Private Key file (.pem) for an extra security layer.
* **Batch Processing:** Allowing users to encode or decode multiple images in a single operation.
* **Network Integration:** Extending the tool to directly send stego images via secure socket connections.
