# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""A sample KmsClient implementation."""
import argparse
import base64
import os
import time
import requests

import pyarrow as pa
import sys
import subprocess
import signal
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe


class VaultClient(pe.KmsClient):
    """An example of a KmsClient implementation with master keys
    managed by Hashicorp Vault KMS.
    See Vault documentation: https://www.vaultproject.io/api/secret/transit
    Not for production use!
    """
    JSON_MEDIA_TYPE = "application/json; charset=utf-8"
    DEFAULT_TRANSIT_ENGINE = "/v1/transit/"
    WRAP_ENDPOINT = "encrypt/"
    UNWRAP_ENDPOINT = "decrypt/"
    TOKEN_HEADER = "X-Vault-Token"

    def __init__(self, kms_connection_config):
        """Create a VaultClient instance.

        Parameters
        ----------
        kms_connection_config : KmsConnectionConfig
           configuration parameters to connect to vault,
           e.g. URL and access token
        """
        pe.KmsClient.__init__(self)
        self.kms_url = kms_connection_config.kms_instance_url + \
            VaultClient.DEFAULT_TRANSIT_ENGINE
        self.kms_connection_config = kms_connection_config

    def wrap_key(self, key_bytes, master_key_identifier):
        """Call Vault to wrap key key_bytes with key
        identified by master_key_identifier."""
        endpoint = self.kms_url + VaultClient.WRAP_ENDPOINT
        headers = {VaultClient.TOKEN_HEADER:
                   self.kms_connection_config.key_access_token}
        r = requests.post(endpoint + master_key_identifier,
                          headers=headers,
                          data={'plaintext': base64.b64encode(key_bytes)},
                          verify=os.environ.get('VAULT_CACERT', 'true'))
        r.raise_for_status()
        r_dict = r.json()
        wrapped_key = r_dict['data']['ciphertext']
        return wrapped_key

    def unwrap_key(self, wrapped_key, master_key_identifier):
        """Call Vault to unwrap wrapped_key with key
        identified by master_key_identifier"""
        endpoint = self.kms_url + VaultClient.UNWRAP_ENDPOINT
        headers = {VaultClient.TOKEN_HEADER:
                   self.kms_connection_config.key_access_token}
        r = requests.post(endpoint + master_key_identifier,
                          headers=headers,
                          data={'ciphertext': wrapped_key},
                          verify=os.environ.get('VAULT_CACERT', 'true'))
        r.raise_for_status()
        r_dict = r.json()
        plaintext = r_dict['data']['plaintext']
        key_bytes = base64.b64decode(plaintext)
        return key_bytes


def parquet_write_read_with_vault(parquet_filename):
    """An example for writing an encrypted parquet and reading an
    encrypted parquet using master keys managed by Hashicorp Vault KMS.
    Note that for this implementation requests dependency is needed
    and environment properties VAULT_URL and VAULT_TOKEN should be set.
    Please enable the transit engine.
    """
    path = parquet_filename

    table = pa.Table.from_pydict({
        'a': pa.array([1, 2, 3]),
        'b': pa.array(['a', 'b', 'c']),
        'c': pa.array(['x', 'y', 'z'])
    })

    # Encrypt the footer with the footer key,
    # encrypt column `a` with one key
    # and column `b` with another key,
    # keep `c` plaintext
    footer_key_name = "footer_key"
    col_a_key_name = "col_a_key"
    col_b_key_name = "col_b_key"

    encryption_config = pe.EncryptionConfiguration(
        footer_key=footer_key_name,
        column_keys={
            col_a_key_name: ["a"],
            col_b_key_name: ["b"],
        })

    kms_connection_config = pe.KmsConnectionConfig(
        kms_instance_url=os.environ.get('VAULT_URL', ''),
        key_access_token=os.environ.get('VAULT_TOKEN', ''),
    )

    def kms_factory(kms_connection_configuration):
        return VaultClient(kms_connection_configuration)

    # Write with encryption properties
    crypto_factory = pe.CryptoFactory(kms_factory)
    file_encryption_properties = crypto_factory.file_encryption_properties(
        kms_connection_config, encryption_config)
    with pq.ParquetWriter(path,
                          table.schema,
                          encryption_properties=file_encryption_properties) \
            as writer:
        writer.write_table(table)

    # Read with decryption properties
    file_decryption_properties = crypto_factory.file_decryption_properties(
        kms_connection_config)
    result = pq.ParquetFile(
        path, decryption_properties=file_decryption_properties)
    result_table = result.read()
    assert table.equals(result_table)


def main():
    VAULT_IS_RUNNING = False
    # Start vault server if not already running
    # check if process name "vault" is running
    for line in os.popen("ps ax | grep vault"):
        fields = line.split()
        pid = fields[0]
        process = fields[4]
        if process == "vault":
            VAULT_IS_RUNNING = True
            print("Vault server is already running")
            break

    if not VAULT_IS_RUNNING:
        print("Starting vault server")
        v = subprocess.Popen(["vault", "server", "-config=vault.hcl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        time.sleep(3)    

    # Initialize vault if not already initialized, automatically unseal
    if not os.path.exists("vault/"):
        print("Initializing vault")
        p = subprocess.Popen(["vault", "operator", "init"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        time.sleep(3)
        out, err = p.communicate()

        unseal_key_file = open("UNSEAL_KEY", "w")
        root_token_file = open("ROOT_TOKEN", "w")
        for line in out.decode("utf-8").splitlines():
            print(line)
            if line.startswith("Unseal Key"):
                unseal_key = line.split()[3]
                print("Unsealing vault with key: " + unseal_key)
                subprocess.Popen(["vault", "operator", "unseal", unseal_key], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                unseal_key_file.write(unseal_key + "\n")
            if line.startswith("Initial Root Token"):
                root_token = line.split()[3]
                root_token_file.write(root_token + "\n")
        sys.exit(0)
        unseal_key_file.close()
        root_token_file.close()

    os.environ["VAULT_CACERT"] = "/workspaces/parqencr/vault.crt"
    parser = argparse.ArgumentParser(
        description="Write and read an encrypted parquet using master keys "
        "managed by Hashicorp Vault.\nBefore using please enable the "
        "transit engine in Vault and set VAULT_URL and VAULT_TOKEN "
        "environment variables.")
    parser.add_argument('--filename', dest='filename', type=str,
                        default='encrypted_table.vault.parquet',
                        help='Filename of the parquet file to be created '
                             '(default: encrypted_table.vault.parquet')
    args = parser.parse_args()
    filename = args.filename
    parquet_write_read_with_vault(filename)
    p.send_signal(signal.SIGINT)
    time.sleep(3)

if __name__ == '__main__':
    main()