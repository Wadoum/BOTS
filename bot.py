import os, logging
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from llama_cpp import Llama
from huggingface_hub import hf_hub_download

logging.basicConfig(level=logging.INFO)
TOKEN = os.environ["TELEGRAM_TOKEN"]

# DeepSeek-R1-Distill-Qwen-7B (GGUF Q4_K_M) — le meilleur compromis taille/qualité
MODEL_REPO = "unsloth/DeepSeek-R1-Distill-Qwen-7B-GGUF"
MODEL_FILE = "DeepSeek-R1-Distill-Qwen-7B-Q4_K_M.gguf"

print("Téléchargement du modèle (environ 4.4 Go)...")
model_path = hf_hub_download(repo_id=MODEL_REPO, filename=MODEL_FILE)

print("Chargement du modèle en mémoire...")
# n_ctx=4096 est un bon compromis pour la RAM
llm = Llama(model_path=model_path, n_ctx=4096, n_threads=4, verbose=False)

async def handle(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user_msg = update.message.text
    await update.message.chat.send_action("typing")

    out = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": "Tu es un assistant utile et direct."},
            {"role": "user", "content": user_msg},
        ],
        max_tokens=1024,   # DeepSeek-R1 a besoin de place pour son raisonnement
        temperature=0.6,   # Recommandé pour les tâches analytiques
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
