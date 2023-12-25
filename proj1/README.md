# Projekt 1 - IPK 2019/2020

#### Funkcionalita:

The program processes GET/POST requests in the HTTP format from the client and returns a response with a header. The header includes the return code and the length of the response in bytes.

#### Spustenie:

```sh
make run PORT=$number
```

kde: $number = 0-65535

#### Functions:

**_get(typ,name)_**
name = IPv4 address/domain name \
typ = A, (Assignment of IPv4 address to domain name) \

typ = PTR, (Assignment of domain name to IP address) \

Returns _ERR_BAD_REQ_ or _0_

**_post(body)_**
body = list of client requests \

Processes client requests using the get() function. If the request is invalid or no response is found, the request is skipped. If nothing is found in the entire list, the function returns ERR_NOT_FOUND. If at least one request is found, the function returns the response.

**_get_answer(message)_**
The function processes input from the client. It returns a response to the client with an HTTP header.
