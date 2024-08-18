#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 10
#define RST_PIN 5
MFRC522 mfrc522(SS_PIN, RST_PIN); // Create an instance of MFRC522.
MFRC522::MIFARE_Key key; // Create a MIFARE_Key struct named 'key', which will hold the card information

void setup() {
    Serial.begin(9600); // Start communication with the computer
    SPI.begin();        // Initiate SPI communication 
    mfrc522.PCD_Init(); // Initiate the RFID reader
    Serial.println("Scan a MIFARE Classic card");
    Serial.println();

    // Prepare the security key for the read and write functions
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF; // Default key value
    }
}

void loop() {
    if (!mfrc522.PICC_IsNewCardPresent()) {
        return; // Exit the loop if no card is found or detected
    }

    if (!mfrc522.PICC_ReadCardSerial()) {
        return; // Exit the loop if card reading fails
    }

    // Display ID of the card on the serial monitor
    Serial.print("Card ID:  ");
    String cardID = "";   // Store the card ID
    for (byte i = 0; i < mfrc522.uid.size; i++) {
        Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");             // Format ID with leading zero
        Serial.print(mfrc522.uid.uidByte[i], HEX);                            // Print ID in hexadecimal
        cardID.concat(String(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " "));    // Store ID
        cardID.concat(String(mfrc522.uid.uidByte[i], HEX));
    }
    Serial.println();

    cardID.toUpperCase(); // Convert cardID to uppercase

    if (cardID.substring(1) == "A3 B6 9C 29") { // Change this to the authorized card's ID
        Serial.println("********************");
        Serial.println("*  Access granted!  *");
        Serial.println("********************");
        Serial.println("\"Welcome John Doe\"");
        delay(3000); // Wait for a few seconds

        // The string to be written, split into 2 blocks (16 bytes each)
        byte hashData[2][16] = {
            {0xc5, 0x37, 0xc6, 0x5b, 0xbd, 0xac, 0x6d, 0xb7, 0x27, 0x63, 0x87, 0x3c, 0xc2, 0xc6, 0x03, 0xec},
            {0x69, 0x6b, 0x43, 0xa3, 0x69, 0x1f, 0x3f, 0xb8, 0x19, 0xf6, 0xac, 0x86, 0xa4, 0x1c, 0x05, 0x02}
        };

        // The private key split across multiple blocks
        byte privateKeyData[2][16] = {
            {0x39, 0x32, 0x30, 0x36, 0x33, 0x34, 0x32, 0x39, 0x34, 0x39, 0x36, 0x35, 0x33, 0x37, 0x30, 0x35}, // Block 4
            {0x33, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        };

        int hashBlocks[] = {2, 6}; // Blocks to write/read the hash data
        int privateKeyBlocks[] = {4, 8,}; // Blocks to write/read the private key

        byte readbackblock[18];
        String combinedHashData = "";
        String combinedPrivateKey = "";

        // Writing and reading hash data
        for (int i = 0; i < 2; i++) {
            int blockNumber = hashBlocks[i];
            if (writeBlock(blockNumber, hashData[i]) != 0) {
                Serial.print("Failed to write to block ");
                Serial.println(blockNumber);
            } else {
                readBlock(blockNumber, readbackblock);
                Serial.print("Read block ");
                Serial.print(blockNumber);
                Serial.print(": ");
                for (int j = 0; j < 16; j++) {
                    Serial.write(readbackblock[j]);
                }
                Serial.println();

                // Append block data to combinedHashData
                for (int j = 0; j < 16; j++) {
                    combinedHashData += String(readbackblock[j] < 16 ? "0" : "") + String(readbackblock[j], HEX);
                }
            }
        }

        // Writing and reading private key data
        for (int i = 0; i < 2; i++) {
            int blockNumber = privateKeyBlocks[i];
            if (writeBlock(blockNumber, privateKeyData[i]) != 0) {
                Serial.print("Failed to write to block ");
                Serial.println(blockNumber);
            } else {
                readBlock(blockNumber, readbackblock);
                Serial.print("Read block ");
                Serial.print(blockNumber);
                Serial.print(": ");
                for (int j = 0; j < 16; j++) {
                    Serial.write(readbackblock[j]);
                }
                Serial.println();

                // Append block data to combinedPrivateKey
                for (int j = 0; j < 16; j++) {
                    combinedPrivateKey += String((char)readbackblock[j]);
                }
            }
        }

        Serial.println("Block was written");
        Serial.println("Block was read");
        Serial.println();
        Serial.print("Hash data: ");
        Serial.println(combinedHashData);
        Serial.print("Private data: ");
        Serial.println(combinedPrivateKey);

    } else {
        Serial.println("Access denied. Unauthorized card.");
        delay(3000); // Wait for a few seconds
    }

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
}

int writeBlock(int blockNumber, byte arrayAddress[]) {
    int largestModulo4Number = blockNumber / 4 * 4;
    int trailerBlock = largestModulo4Number + 3;
    if (blockNumber % 4 == 3) {
        Serial.print(blockNumber);
        Serial.println(" is a trailer block:");
        return 2;
    }
    Serial.print(blockNumber);
    Serial.println(" is a data block:");

    byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print("PCD_Authenticate() failed: ");
        Serial.println(mfrc522.GetStatusCodeName(status));
        return 3;
    }

    status = mfrc522.MIFARE_Write(blockNumber, arrayAddress, 16);
    if (status != MFRC522::STATUS_OK) {
        Serial.print("MIFARE_Write() failed: ");
        Serial.println(mfrc522.GetStatusCodeName(status));
        return 4;
    }
    Serial.println("Block was written");
    return 0;
}

int readBlock(int blockNumber, byte arrayAddress[]) {
    int largestModulo4Number = blockNumber / 4 * 4;
    int trailerBlock = largestModulo4Number + 3;

    byte status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print("PCD_Authenticate() failed (read): ");
        Serial.println(mfrc522.GetStatusCodeName(status));
        return 3;
    }

    byte buffersize = 18;
    status = mfrc522.MIFARE_Read(blockNumber, arrayAddress, &buffersize);
    if (status != MFRC522::STATUS_OK) {
        Serial.print("MIFARE_read() failed: ");
        Serial.println(mfrc522.GetStatusCodeName(status));
        return 4;
    }
    Serial.println("Block was read");
    return 0;
}