import docopt

from . import armor
from . import debug
from . import encrypt
from . import sign

__doc__ = '''\
Usage:
    saltpack encrypt [<private>] [<recipients>...] [options]
    saltpack decrypt [<private>] [options]
    saltpack sign [<private>] [options]
    saltpack verify [options]
    saltpack armor [<bytes>] [options]
    saltpack dearmor [<chars>] [options]
    saltpack block [<bytes>] [options]
    saltpack unblock [<chars>] [options]
    saltpack efficient <alphabet_size> [<max-size>]

For encrypt, if no private key is given, the default is 32 zero bytes. If no
recipients are given, the default is the sender's own public key.

For signing, if no private key is given, the default is a random key.

Options:
    --alphabet=<str>                the alphabet string to index into when armoring
    -b --binary                     don't use saltpack armor
    --base64                        for armor, use the Base64 alphabet and 3-byte blocks
    --base85                        for armor, use the Base85 alphabet and 4-byte blocks
    --block=<size>                  the armoring block size
    --chunk=<size>                  size of payload chunks, default 1 MB
    -d --detached                   make a detached signature
    --debug                         debug mode
    -m --message=<msg>              message text, instead of reading stdin
    --major-version=<major-version> saltpack major version used for encryption
    --raw                           omit armor header and footer
    --shift                         shift the encoded number left as far as possible
    -s --signature=<file>           verify with a detached signature
    --twitter                       for armor, use the Twitter alphabet
    --visible                       make the encryption recipients visible
'''

FORMAT_VERSION = 1


def main():
    args = docopt.docopt(__doc__)
    debug.DEBUG_MODE = args['--debug']

    if args['efficient']:
        armor.do_efficient(args)
    elif args['block']:
        armor.do_block(args)
    elif args['unblock']:
        armor.do_unblock(args)
    elif args['armor']:
        armor.do_armor(args)
    elif args['dearmor']:
        armor.do_dearmor(args)
    elif args['encrypt']:
        encrypt.do_encrypt(args)
    elif args['decrypt']:
        encrypt.do_decrypt(args)
    elif args['sign']:
        sign.do_sign(args)
    elif args['verify']:
        sign.do_verify(args)
    else:
        raise RuntimeError("unreachable")
