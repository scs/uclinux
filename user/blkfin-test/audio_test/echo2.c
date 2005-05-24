/* program to get around missing redirection in sash */

#include <stdio.h>

int main(int argc, char* argv[]){

  FILE* f;

  if( argc < 3 ){
    fprintf( stderr, "usage: %s file string...\n", argv[0] );
    exit(1);
  }
    
  if( (f=fopen(argv[1], "w")) == NULL ){
    fprintf( stderr, "%s:could not open %s for writing.\n", argv[0], argv[1] );
    exit(2);
  }

  argc-=2;
  argv+=2;

  while( argc-- ){
    fputs( *argv++, f );
    if( argc ) fputs( " ", f );
  }
  
  fputs( "\n", f );

  fflush(f);

  fclose(f);

  return 0;
}
