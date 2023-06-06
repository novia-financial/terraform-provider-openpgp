package pgp

const NameLengthMinimum int = 0
const NameLengthMaximum int = 256

const PassphraseLengthMinimum int = 1
const PassphraseLengthMaximum int = 100

const ExpiryInDaysMinimum int = 1
const ExpiryInDaysMaximum int = 1_000

const EncodingType_Base64 string = "base64"
const EncodingType_Armored string = "armored"

const KeyType_Rsa string = "rsa"
const KeyType_RsaBits int = 2048
