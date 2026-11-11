# Entrega 1 — Criptografia assimétrica e confiança

Projeto Integrador · Segurança Aplicada ao Desenvolvimento · UNIT
Opção escolhida: **assinatura digital com Ed25519**.

## 1. Problema e objetivo
Uma aplicação precisa enviar uma mensagem a outro serviço e permitir que o
destinatário **verifique a autenticidade** (quem enviou) e a **integridade**
(ninguém alterou). Objetivo: gerar chaves, assinar, verificar e demonstrar
que a verificação **falha** quando a mensagem é adulterada.

## 2. Ambiente e tecnologias
- Python 3.12 (funciona em 3.9+)
- Biblioteca `cryptography` (consolidada; nenhum algoritmo foi implementado à mão)
- Testes com `unittest` (biblioteca padrão)

## 3. Algoritmos, parâmetros e justificativa
| Item | Escolha | Por quê |
|---|---|---|
| Assinatura | Ed25519 (EdDSA, curva 25519) | Moderno, rápido, parâmetros fixos (sem escolhas inseguras), assinatura determinística |
| Tamanhos | chave 32 bytes · assinatura 64 bytes | Padrão do algoritmo |
| Formato das chaves | PEM (PKCS#8 privada / SubjectPublicKeyInfo pública) | Formato padrão e interoperável |
| Proteção da privada | `BestAvailableEncryption` (cifrada com senha) | Se o arquivo vazar, não serve sem a senha |
| Transporte da assinatura | Base64 dentro de um JSON | Texto simples, fácil de enviar |

## 4. Implementação e execução
```bash
pip install -r requirements.txt

python main.py gerar-chaves              # cria chaves/privada.pem e chaves/publica.pem
python main.py assinar "Olá, serviço B" -o mensagem.json
python main.py verificar mensagem.json   # ASSINATURA VÁLIDA
python main.py demo                      # cenário completo (sucesso + falhas)
python test_assinatura.py                # 11 testes automatizados
```
A senha da chave privada é pedida no terminal ou lida da variável de ambiente
`CHAVE_SENHA`. Nunca fica gravada no código.

Arquivos: `assinatura.py` (funções de cripto) · `main.py` (linha de comando) ·
`test_assinatura.py` (testes) · `evidencias/` (saídas reais da execução).

## 5. Testes e evidências
Saídas em `evidencias/testes.txt` e `evidencias/demo.txt`.

| Cenário | Resultado esperado | Obtido |
|---|---|---|
| Mensagem original | Válida | ✅ Válida |
| Mensagem adulterada | Inválida | ✅ Inválida |
| Assinatura adulterada | Inválida | ✅ Inválida |
| Chave pública de outra pessoa | Inválida | ✅ Inválida |
| Envelope malformado / algoritmo trocado | Inválida (sem travar) | ✅ Inválida |
| Senha errada na chave privada | Erro | ✅ Erro |
| Privada gravada cifrada, permissão 0600 | Sim | ✅ Sim |

## 6. Sigilo x autenticidade (diferença pedida)
- **Sigilo (confidencialidade):** impede que terceiros **leiam**. Vem da **cifragem**.
  *Analogia: envelope lacrado.*
- **Autenticidade (+ integridade):** prova **quem enviou** e que **não foi alterado**.
  Vem da **assinatura digital**. *Analogia: assinatura reconhecida em cartório.*
- **Esta entrega assina, mas não cifra.** A mensagem continua legível; só não pode
  ser alterada nem forjada sem ser detectada. Para ter os dois, usa-se cifragem
  híbrida (AES-GCM + RSA-OAEP) **e** assinatura.

## 7. Certificados digitais e PKI
- Uma chave pública sozinha **não diz de quem ela é**. Qualquer pessoa pode gerar um par e dizer "sou o Banco X".
- **Certificado digital** (padrão X.509) = documento que liga uma **identidade** a uma **chave pública**, assinado por uma **Autoridade Certificadora (AC)**. *Analogia: RG — a chave pública é a foto, a AC é o órgão que emitiu.*
- **PKI (Infraestrutura de Chaves Públicas)** = AC + regras + validação + revogação (CRL/OCSP) + cadeia de confiança (AC raiz → intermediária → certificado final).
- **Neste projeto:** a chave pública é entregue diretamente ao destinatário (confiança manual). Em produção, usaríamos um certificado emitido por uma AC.

## 8. Gestão de chaves
- Privada: cifrada com senha, permissão 0600, **fora do Git** (`.gitignore`).
- Pública: pode ser distribuída livremente.
- Não há rotação, revogação nem cofre de chaves automáticos (ver limites).

## 9. Riscos, limitações e melhorias
| Limite | Impacto | Melhoria |
|---|---|---|
| Não há sigilo (mensagem legível) | Qualquer um lê | Adicionar cifragem híbrida AES-GCM + RSA-OAEP |
| Sem proteção contra **replay** (reenvio de mensagem válida antiga) | Mensagem antiga aceita de novo | Incluir timestamp + nonce na assinatura |
| Chave pública distribuída sem certificado | Confiança manual | Usar certificado X.509 / PKI |
| Sem revogação/rotação de chaves | Chave vazada continua válida | Política de rotação e lista de revogação |
| Senha da privada vem do usuário | Senha fraca enfraquece a proteção | Cofre de segredos (KMS/Vault), senha forte |

## 10. Mapeamento aos padrões da disciplina
- OWASP Top 10:2025 — **A04** Falhas criptográficas
- OWASP ASVS 5.0 — **V11** Criptografia · **V12** Comunicação segura
- ISO/IEC 27002:2022 — **8.24** Uso de criptografia

## 11. Referências
- Documentação oficial da biblioteca `cryptography` (cryptography.io) — Ed25519 e serialização de chaves
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 5280 — Certificados X.509 e PKI
- OWASP Top 10:2025; OWASP ASVS 5.0; ISO/IEC 27001 e 27002:2022
- Material da aula: Segurança Aplicada ao Desenvolvimento (Profa. Ana Carla do Nascimento Santos)
