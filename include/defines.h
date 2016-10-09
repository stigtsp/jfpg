#define FILENAME_SIZE   255
#define EXT     ".jfpg"
#define SIGNEXT ".signed"
#define PUB     "-pubkey.curve25519"
#define SEC     "-secretkey.curve25519"
#define PUBSIGN "-signing-pubkey.ed25519"
#define SECSIGN "-signing-secretkey.ed25519"

#define	ARGON2_T	11
#define ARGON2_MEM	512
#define ARGON2_P	2
#define MIN_ROUNDS      4
#define MAX_ROUNDS      1024
#define	MIN_MEM		56
#define	MAX_MEM		32000

#define IDSIZE  	128
#define B64NAMESIZE     192
#define PUBKEYBYTES     crypto_box_PUBLICKEYBYTES
#define SECKEYBYTES     crypto_box_SECRETKEYBYTES
#define NONCEBYTES      crypto_box_NONCEBYTES
#define ZEROBYTES       crypto_box_ZEROBYTES
#define SIGNSKEYBYTES   crypto_sign_SECRETKEYBYTES
#define SIGNPKEYBYTES   crypto_sign_PUBLICKEYBYTES