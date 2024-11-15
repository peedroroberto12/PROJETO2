#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>

#define MAX_LINES 30
#define MAX_LEN 30

void buscarLinha(const char *nome_arquivo, const char *linha_procurada) {
    FILE *arquivo = fopen(nome_arquivo, "r");  // Abre o arquivo no modo de leitura
    if (arquivo == NULL) {
        printf("Erro ao abrir o arquivo %s\n", nome_arquivo);
        return;
    }

    char linha[256];  // Buffer para armazenar cada linha do arquivo
    while (fgets(linha, sizeof(linha), arquivo)) {  // Lê linha por linha do arquivo
        // Remove o caractere de nova linha no final (caso exista)
        size_t len = strlen(linha);
        if (len > 0 && linha[len - 1] == '\n') {
            linha[len - 1] = '\0';
        }

        if (strcmp(linha, linha_procurada) == 0) {  // Compara a linha lida com a linha procurada
            printf("Encontrado\n");
            fclose(arquivo);
            return;  // Linha encontrada, encerra a função
        }
    }

    printf("Não encontrado\n");
    fclose(arquivo);
}

void codificar(char str[89]) {
    SHA512_CTX ctx;
    unsigned char buffer[SHA512_DIGEST_LENGTH];  
    int len = strlen(str);

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, str, len);
    SHA512_Final(buffer, &ctx); 

    char base64_buffer[89];  
    int base64_len = EVP_EncodeBlock(base64_buffer, buffer, SHA512_DIGEST_LENGTH);
    printf("Base64 Encoded da palavra %s SHA-512 Hash: %s\n", str, base64_buffer);
}

int main(void) {
    int k, j, l, m, n;
    char data[MAX_LINES][MAX_LEN];

    FILE *file;
  
    file = fopen("palavras.txt", "r");

    int line = 0;

    // Lê as palavras do arquivo "palavras.txt"
    while (!feof(file) && !ferror(file)) {
        if (fgets(data[line], MAX_LEN, file) != NULL) {
            size_t len = strlen(data[line]);
            if (len > 0 && data[line][len - 1] == '\n') {
                data[line][len - 1] = '\0'; 
            }
            line++;
        }
    }

    fclose(file);

    FILE *arquivo = fopen("banco.txt", "w+");

    for (int i = 0; i < line; i++) {
        char linha1[500]; 
        sprintf(linha1, "%s\n", data[i]); 
        fputs(linha1, arquivo); 

        for(k = 0; k < 24; k++) {
            char linha2[500]; 
            sprintf(linha2, "%s %s\n", data[i], data[k]);  
            fputs(linha2, arquivo);  

            for(j = 0; j < 24; j++) {
                char linha3[500];
                sprintf(linha3, "%s %s %s\n", data[i], data[k], data[j]);
                fputs(linha3, arquivo);

                for(l = 0; l < 24; l++) {
                    char linha4[500];
                    sprintf(linha4, "%s %s %s %s\n", data[i], data[k], data[j], data[l]);
                    fputs(linha4, arquivo);

                    for(m = 0; m < 24; m++) {
                        char linha5[500];
                        sprintf(linha5, "%s %s %s %s %s\n", data[i], data[k], data[j], data[l], data[m]);
                        fputs(linha5, arquivo);

                    }
                }
            }
        }
    }

    fclose(arquivo);
    return 0;
}
