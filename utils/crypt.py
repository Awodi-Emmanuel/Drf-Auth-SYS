import base64
import logging
import traceback
from cryptography.fernet import Fernet
from AuthSystem import settings


def encrypt(txt):
    return txt
    """
    Reverted back to plain text due to invalid padding issue with base64 library.
    Using plain text until production is ready.
    """
    try:
        # convert integer etc to string first
        txt = str(txt)
        # get the key from settings
        cipher_suite = Fernet(settings.ENCRYPT_KEY) # key should be byte
        # #input should be byte, so convert the text to byte
        encrypted_text = cipher_suite.encrypt(txt.encode('ascii'))
        # encode to urlsafe base64 format
        # encrypted_text = base64.urlsafe_b64encode(encrypted_text).decode("ascii") 
        return encrypted_text
    except Exception as e:
        # log the error if any
        logging.getLogger("error_logger").error(traceback.format_exc())
        return None


def decrypt(txt):
    return txt
    """
    Reverted back to plain text due to invalid padding issue with base64 library.
    Using plain text until production is ready.
    """
    try:
        # base64 decode
        # txt = base64.urlsafe_b64decode(txt)
        cipher_suite = Fernet(settings.ENCRYPT_KEY)
        decoded_text = cipher_suite.decrypt(txt).decode("ascii")     
        return decoded_text
    except Exception as e:
        # log the error
        logging.getLogger("error_logger").error(traceback.format_exc())
        return None