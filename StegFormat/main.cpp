/* 
 * File:   main.cpp
 * Author: afeena
 *
 * Created on April 13, 2015, 1:16 AM
 */

#include <cstdlib>
#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <stdio.h>

using namespace std;

/*
 * 
 */
int main(int argc, char** argv) {
    string addr;
    uint32_t f_addr;
    
    
    f_addr=inet_addr(argv[1]);
    fwrite((char*)&f_addr,1,sizeof(f_addr),stdout);
    printf("%s",argv[2]);
    
    

    return 0;
}

