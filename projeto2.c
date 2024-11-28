#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define MAX_LINES 35
#define MAX_LEN 30

//Palavras tentadas:brownie hamburguer arroz feijao batata sushi macarrao lasanha salmao temaki coxinha gelatina Tapioca Torrada refrigerante
//Faltou encontrar as palavras corretas
// projeto 2 por Pedro Roberto Fernandes Noronha e Gabriel Tortolio e  Pedro Daniel Reis de Souza

int contaPalavra(const char *palavra) {

    int contador = 0;
    for (int i = 0; palavra[i] != '\0'; i++) {
        contador++;
    }
    return contador;
}

void limparString(char *str) {
    
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }

    while (*str && isspace((unsigned char)*str)) {
        str++;
    }

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }

    *(end + 1) = '\0';
}

void codificar(char *str, char *base64_buffer) {
    SHA512_CTX ctx;
    unsigned char buffer[SHA512_DIGEST_LENGTH];
    int len = strlen(str);

    SHA512_Init(&ctx);
    SHA512_Update(&ctx, str, len);
    SHA512_Final(buffer, &ctx);

    EVP_EncodeBlock(base64_buffer, buffer, SHA512_DIGEST_LENGTH);
    limparString(base64_buffer);
}

int compararStrings(const char *string1, const char *string2) {
    if (contaPalavra(string1) != contaPalavra(string2)) {
        return 0;
    }

    for (int i = 0; string1[i] != '\0'; i++) {
        if (string1[i] != string2[i]) {
            return 0;
        }
    }

    return 1;
}

int buscarLinha(const char *linha_procurada, char *usuario) {
    const char *nome_arquivo = "usuarios_senhascodificadas2.txt";
    FILE *arquivo = fopen(nome_arquivo, "r");
    if (arquivo == NULL) {
        printf("Erro ao abrir o arquivo %s\n", nome_arquivo);
        return 0;
    }

    char linha[256];
    char *senha_codificada;

    while (fgets(linha, sizeof(linha), arquivo)) {

        limparString(linha);

        char *usuario_atual = linha;
        senha_codificada = strchr(linha, ':');

        if (senha_codificada != NULL) {

            *senha_codificada = '\0';
            senha_codificada++;

            limparString(usuario_atual);

            limparString(senha_codificada);

            if (compararStrings(senha_codificada, linha_procurada) == 1) {
                strcpy(usuario, usuario_atual);
                fclose(arquivo);
                return 1;
            }
        }
    }
    fclose(arquivo);
    return 0;
}

int main(void) {
    int k, j, l, m, n;
    char data[MAX_LINES][MAX_LEN];
    FILE *file;

    FILE *saida = fopen("senhas_quebradas.txt", "w");
    if (saida == NULL) {
        printf("Erro ao abrir o arquivo de saída.\n");
        return 1;
    }

    file = fopen("palavras.txt", "r");

    int line = 0;
    while (!feof(file) && !ferror(file)) {
        if (fgets(data[line], MAX_LEN, file) != NULL) {
            limparString(data[line]);
            line++;
        }
    }

    fclose(file);

    for (int i = 0; i < line; i++) {
        char linha1[500];
        sprintf(linha1, "%s", data[i]);

        char linha1h[500];
        codificar(linha1, linha1h);

        limparString(linha1h);

        char usuario[250];
        if (buscarLinha(linha1h, usuario)) {
            fprintf(saida, "%s: %s\n", usuario, linha1);
        }

        for (k = 0; k < line; k++) {
            char linha2[500];
            sprintf(linha2, "%s %s", data[i], data[k]);

            char linha2h[500];
            codificar(linha2, linha2h);

            limparString(linha2h);

            if (buscarLinha(linha2h, usuario)) {
                fprintf(saida, "%s: %s\n", usuario, linha2);
            }

            for (l = 0; l < line; l++) {
                char linha3[500];
                sprintf(linha3, "%s %s %s", data[i], data[k], data[l]);

                char linha3h[500];
                codificar(linha3, linha3h);

                limparString(linha3h);

                if (buscarLinha(linha3h, usuario)) {
                    fprintf(saida, "%s: %s\n", usuario, linha3);
                }

                for (m = 0; m < line; m++) {
                    char linha4[500];
                    sprintf(linha4, "%s %s %s %s", data[i], data[k], data[l], data[m]);

                    char linha4h[500];
                    codificar(linha4, linha4h);

                    limparString(linha4h);

                    if (buscarLinha(linha4h, usuario)) {
                        fprintf(saida, "%s: %s\n", usuario, linha4);
                    }

                    for (n = 0; n < line; n++) {
                        char linha5[500];
                        sprintf(linha5, "%s %s %s %s %s", data[i], data[k], data[l], data[m], data[n]);

                        char linha5h[500];
                        codificar(linha5, linha5h);

                        limparString(linha5h);

                        if (buscarLinha(linha5h, usuario)) {
                            fprintf(saida, "%s: %s\n", usuario, linha5);
                        }
                    }
                }
            }
        }
    }

    fclose(saida);
    printf("Processo concluído.\n");

    return 0;
}
