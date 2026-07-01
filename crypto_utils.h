#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace crypto {

/**
 * Converte bytes para string hexadecimal.
 * Útil para exibir hashes e salts de forma legível.
 */
std::string bytes_to_hex(const std::vector<uint8_t>& data);

/**
 * Converte string hexadecimal para bytes.
 * Inverso do bytes_to_hex.
 */
std::vector<uint8_t> hex_to_bytes(const std::string& hex);

/**
 * Calcula hash SHA-256 de um bloco de dados.
 * Retorna 32 bytes (256 bits).
 */
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

/**
 * Gera bytes aleatórios criptograficamente seguros.
 * Usa /dev/urandom (Linux/Mac) ou BCryptGenRandom (Windows).
 */
std::vector<uint8_t> random_bytes(size_t count);

/**
 * Compara dois vetores de bytes em tempo constante.
 * Previne timing attacks.
 */
bool secure_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

/**
 * Formata tamanho de arquivo em string legível.
 * Ex: 1536 → "1.5 KB"
 */
std::string format_file_size(uint64_t bytes);

/**
 * Cabeçalho de arquivo criptografado.
 * Armazena salt e metadados para descriptografia.
 */
struct CryptoHeader {
    static constexpr uint32_t MAGIC = 0x454E4352; // "ENCR"
    static constexpr uint8_t VERSION = 1;

    uint32_t magic;          // Identificador do formato
    uint8_t version;         // Versão do formato
    uint32_t salt_size;      // Tamanho do salt em bytes
    std::vector<uint8_t> salt; // Salt para derivação de chave
    uint32_t iterations;     // Iterações do PBKDF2
    uint64_t original_size;  // Tamanho original do arquivo

    CryptoHeader();

    /**
     * Serializa o cabeçalho para bytes.
     */
    std::vector<uint8_t> serialize() const;

    /**
     * Deserializa bytes para cabeçalho.
     * Retorna true se válido.
     */
    bool deserialize(const std::vector<uint8_t>& data);

    /**
     * Tamanho total do cabeçalho serializado.
     */
    size_t total_size() const;
};

} // namespace crypto

#endif // CRYPTO_UTILS_H
