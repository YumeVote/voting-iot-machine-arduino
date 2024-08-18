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
    Serial.println("Hold your National ID Card close to the reader...");

    // Prepare the security key for the read function
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF; // Default key value
    }
}

void loop() {
    if (!mfrc522.PICC_IsNewCardPresent()) {
        return; // Exit the loop if no card is found or detected.
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

    // Check if the card ID is authorized
    if (cardID.substring(1) == "A3 B6 9C 29") { // Change this to the authorized card's ID
        Serial.println("********************");
        Serial.println("*  Access granted!  *");
        Serial.println("CARD_READING");
        Serial.println("                     ");
        delay(3000); // Wait for a few seconds

        // Read data from specified blocks
        int blockNumbers[] = {2, 6}; // Block numbers to read
        byte readbackblock[18];
        String combinedData = "";

        for (int i = 0; i < 2; i++) {
            int blockNumber = blockNumbers[i];
            if (readBlock(blockNumber, readbackblock) != 0) {
                Serial.print("Failed to read from block ");
                Serial.println(blockNumber);
            } else {
                Serial.print("Read block ");
                Serial.print(blockNumber);
                Serial.print(": ");
                for (int j = 0; j < 16; j++) {
                    Serial.print(readbackblock[j] < 16 ? "0" : ""); // Print leading zero if needed
                    Serial.print(readbackblock[j], HEX);
                }
                Serial.println();
                
                // Append block data to combinedData
                for (int j = 0; j < 16; j++) {
                    combinedData += String(readbackblock[j] < 16 ? "0" : "") + String(readbackblock[j], HEX);
                }
            }
        }

        // Read additional blocks 4 and 8 for private key
        byte block4Data[18], block8Data[18];
        String block4Str = "", block8Str = "";
        
        if (readBlock(4, block4Data) == 0) {
            Serial.print("Read Block 4: ");
            for (int j = 0; j < 16; j++) {
                block4Str += String(block4Data[j] < 16 ? "0" : "") + String(block4Data[j], HEX);
            }
            Serial.println(block4Str);
        }
        
        if (readBlock(8, block8Data) == 0) {
            Serial.print("Read Block 8: ");
            for (int j = 0; j < 16; j++) {
                block8Str += String(block8Data[j] < 16 ? "0" : "") + String(block8Data[j], HEX);
            }
            Serial.println(block8Str);
        }

        // Format private key and hash output
        String privateKey = block4Str + block8Str;
        String hash = combinedData;

        // Output formatted results
        Serial.print("ACCESS_GRANTED_PRIVATE_KEY ");
        Serial.println(privateKey);
        Serial.print("ACCESS_GRANTED_HASH ");
        Serial.println(hash);
        Serial.print("ACCESS_GRANTED_ID ");
        Serial.println(cardID.substring(1)); // Send card ID to indicate access granted
    } else {
        Serial.println("Access denied. Unauthorized card.");
        Serial.print("ACCESS_DENIED ");
        Serial.println(cardID.substring(1)); // Send card ID to indicate access denied
        delay(3000); // Wait for a few seconds
    }
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