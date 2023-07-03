

## Get the master fingerprint

```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./run.sh --get_master_fingerprint
```

## Get a segwit address:

PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./run.sh --get_wallet_address --descriptor_template "wpkh(@0/**)" --keys_info "[\"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK\"]"

Correct answer: tb1qh07qqlkgskfethz644q25ls2qwm6uxtl5dsr44


## Register a wallet

```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./run.sh --register_wallet --name "Cold storage" --descriptor_template "sh(wsh(sortedmulti(2,@0/**,@1/**)))" --keys_info "[\"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g\",\"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY\"]"
```

(currently returning a dummy HMAC)


## Get an address for a multisig wallet (veeeery slow)

```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./run.sh --get_wallet_address --name "Cold storage" --descriptor_template "sh(wsh(sortedmulti(2,@0/**,@1/**)))" --keys_info "[\"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g\",\"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY\"]"
```


## Get address for a simple miniscript policy (also slow):


```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./run.sh --get_wallet_address --name "One of 2" --descriptor_template "wsh(or_d(pk(@0/**),pkh(@1/**)))" --keys_info "[\"tpubDDs8xyRFagmDPgHPuCLLbyELucXAbyER4bGBUMs9QTX3EnBnXjBd2v91J6Ychxh79qDzRhg3dZarNNbatnWTxRZvdYs2m4X7FoBqtW5vHHJ\",\"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK\"]"
```

correct answer: "tb1q5x0each5rwzgprv2fh2pznj3hr2y7mu27d7zufstfhgq2n48ur6qnhex9r"




## A complicated policy with miniscript:

```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./run.sh --get_wallet_address --name "Policy with a:" --descriptor_template "wsh(or_i(and_v(v:pkh(@0/**),older(65535)),or_d(multi(2,@1/**,@2/**),and_v(v:thresh(1,pkh(@3/**),a:pkh(@4/**)),older(64231)))))" --keys_info "[\"tpubDDs8xyRFagmDPgHPuCLLbyELucXAbyER4bGBUMs9QTX3EnBnXjBd2v91J6Ychxh79qDzRhg3dZarNNbatnWTxRZvdYs2m4X7FoBqtW5vHHJ\",\"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK\",\"tpubDD7LrDyejF7zs1feqpXgsMHjyAKL87PksghmqHVxk2ba41ZXhR1CR3K3Ng1mviRePiQMB5gVYfuty8UUqUGZpiitj4cdg3ANwF6F1pPKLja\",\"tpubDCsRLbMWqyA5JQUSimZ56xQ41BSXssyndG97b9Tm9iRE5WndUEKCzqn8C3ziQ2ByFuB67Vn3QxhJgDRrC5v2mfyYWLei3dLPRBprtN8tcxq\",\"tpubDDEn7rmHD98vTie4rXN1LLtErWpYuZAMAr8oXFSnqwbH4kE2kLreu9X8qMw4uRqotQpdBZenXAM2oR3djj8bvWfdaJxB4QyPdiqh4oSQmss\"]"
```


# Sign a psbt

## P2PKH

```
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./run.sh --sign_psbt --name "" --descriptor_template "pkh(@0/**)" --keys_info "[\"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT\"]" --psbt "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA"
```
