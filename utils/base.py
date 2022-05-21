import base64


def url_safe_encode(data: str):
    return data
    """
    Reverted back to plain text due to invalid padding issue with base64 library.
    Using plain text until production is ready.
    """
    return base64.urlsafe_b64encode(data.encode()).decode()


def url_safe_decode(data: str):
    return data
    """
    Reverted back to plain text due to invalid padding issue with base64 library.
    Using plain text until production is ready.
    """
    return base64.urlsafe_b64decode(data).decode()



def base64_encode(string: str):
    return string
    """
    Reverted back to plain text due to invalid padding issue with base64 library.
    Using plain text until production is ready.
    """
    """
    Removes any `=` used as padding from the encoded string.
    """
    encoded = base64.urlsafe_b64encode(string.encode())
    return encoded.rstrip("=")


def base64_decode(string: str):
    return string
    """
    Reverted back to plain text due to invalid padding issue with base64 library.
    Using plain text until production is ready.
    """
    """
    Adds back in the required padding before decoding.
    """
    padding = 4 - (len(string) % 4)
    string = string + ("=" * padding)
    return base64.urlsafe_b64decode(string)