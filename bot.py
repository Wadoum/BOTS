import os, logging
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from llama_cpp import Llama
from huggingface_hub import hf_hub_download

logging.basicConfig(level=logging.INFO)
TOKEN = os.environ["TELEGRAM_TOKEN"]

# Dépôt alternatif, mieux supporté par llama-cpp-python
MODEL_REPO = "SandLogicTechnologies/DeepSeek-R1-Distill-Qwen-7B-GGUF"
MODEL_FILE = "DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf"

print("Téléchargement du modèle...")
model_path = hf_hub_download(repo_id=MODEL_REPO, filename=MODEL_FILE)

# --- Validation du fichier GGUF ---
size_gb = os.path.getsize(model_path) / (1024**3)
print(f"Taille du fichier : {size_gb:.2f} GB")
if size_gb < 1.0:
    raise ValueError(f"Fichier trop petit ({size_gb:.2f} GB), probablement corrompu")

with open(model_path, "rb") as f:
    magic = f.read(4)
if magic != b"GGUF":
    raise ValueError(f"Fichier non-GGUF (magic={magic})")

print("Chargement du modèle...")
llm = Llama(
    model_path=model_path,
    n_ctx=4096,
    n_threads=4,
    verbose=True,
)

async def handle(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user_msg = update.message.text
    await update.message.chat.send_action("typing")

    out = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": "Tu es un assistant utile et direct."},
            {"role": "user", "content": user_msg},
        ],
        max_tokens=1024,
        temperature=0.6,
    )
    reply = out["choices"][0]["message"]["content"]
    await update.message.reply_text(reply[:4000])

def main():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle))
    print("Bot démarré avec DeepSeek 7B...")
    app.run_polling()

if __name__ == "__main__":
    main()
