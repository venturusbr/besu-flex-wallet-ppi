# besu-flex-wallet-ppi

java client that helps us to test Transactions

# How to run

To run the project, follow these steps:

1. Build the project using Maven:
   ```sh
   mvn clean install
   ```
2. Once you have a blockchain network up, send a Transaction running this command:
   ```sh
   mvn exec:java
   ```
3. (Optional) Generate a new key pair before sending the transaction.
   Use the --generateKeys flag if you want to create a new post-quantum key pair:

   ```sh
   mvn exec:java -Dexec.args="--generateKeys"
   ```

   ⚠️ **Note:** This will overwrite any existing key files.
