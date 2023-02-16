# Methodology

We use *three* relevant data structures in order to verify if there is a Buffer Overflow vulnerability: *variables*, *stack*, *registers*

## 1. Variables

We store the data of the variables in a *dictionary* which starts with a simple copy from the JSON input variables block. But we also add the address of the variable in decimal (with `RBP == 0` in the case of `main` function, and stack growing to positive values).

When parsing the assembly (specifically input functions) we add the size of the maximum content stored length (including the '\0').

Moreover, we also add *padding* between variables as a variable of type "unallocated". Example:

```json
[
    {
        'bytes': 4,
        'type': 'int',
        'name': 'control',
        'address': 'rbp-0x4',
        'addr': 4,
        'content_size': None
    },
    {
        'bytes': 12,
        'type': 'unallocated',
        'name': 'unallocated',
        'address': 'rbp-0x10',
        'addr': 16,
        'content_size': None
    },
    {
        'bytes': 32,
        'type': 'buffer',
        'name': 'buf3',
        'address': 'rbp-0x30',
        'addr': 48,
        'content_size': None
    },
    {
        'bytes': 16,
        'type': 'buffer',
        'name': 'buf2',
        'address': 'rbp-0x40',
        'addr': 64,
        'content_size': None
    },
    {
        'bytes': 64,
        'type': 'buffer',
        'name': 'buf1',
        'address': 'rbp-0x80',
        'addr': 128,
        'content_size': None
    }
]

```

For generic functions, we also add the parameters the function receives to the `variables` *dictionary*, as it helps us when checking the addresses of the parameters given to dangerous functions.


## 2. Stack

In the *stack* *dictionary* we add the saved RBP (placed by a `push` instruction) and the size allocated for the local variables (placed by a `sub` or `add` instruction). We calculate the value of the `RSP` register by summing up the size of the stack so far (with `RBP` starting at 0). Example:

```json
[
    {
        'name': 'saved_rbp',
        'size': 8
    },
    {
        'name': 'localvars',
        'size': 224
    }
]
```

This data structure is useful to calculate the value of the `RBP` register, and could become more useful if our tool became more complex.

## 3. Registers

We store the values of the registers used (through the `mov`, `lea`, `push`, `add` and `sub` instructions) so that we can know what parameters are passed to the dangerous functions. Example:

```json
{'RBP': 0, 'RAX': 64, 'RSI': 160, 'RDI': 64, 'RCX': 224, 'RDX': 160}
```

## 4. Parameters

The parameters passed to function calls are stored in registers, by the following order:

```
RDI,RSI,RDX,RCX,R8,R9 + stack for arguments beyond the 6th (with 7th argument being the one on top)
```