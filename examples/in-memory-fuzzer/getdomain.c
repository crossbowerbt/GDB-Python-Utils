#include <stdio.h>
#include <string.h>

void print_domain(char *domain) {
    printf("Domain is %s\n", domain);
}

char *parse(char *str) {
    char buffer[1024];
    char *token, *substr;

    if(!str) {
        return;
    }

    for (substr=str; ; substr=NULL) {
        token = strtok(substr, "@");
        
        if (token==NULL) {
            break;
        }
        
        if (substr==NULL) {
            strcpy(buffer, token);
            print_domain(buffer);
            return "YES";
        }
    }

    return "NO";
}

int main(int argc, char **argv) {

    if (argc<2) {
        puts("./getdomain <email_address>");
        return 1;
    }

    printf("Domain is valid? %s\n", parse(strdup(argv[1])));

    return 0;
}
