import re

AI_FRAMEWORKS = [
    "PyTorch", "TensorFlow", "Keras", "JAX", "MXNet",
    "Transformers", "Hugging Face", "HuggingFace", "Diffusers",
    "LangChain", "LlamaIndex", "vLLM", "Ollama", "llama.cpp",
    "ONNX", "OpenVINO", "TensorRT", "CUDA", "cuDNN",
    "scikit-learn", "XGBoost", "LightGBM", "CatBoost",
    "Stable Diffusion", "OpenAI", "Anthropic", "Claude", "GPT",
    "LLaMA", "Mistral", "Qwen", "Gemma", "Phi", "DeepSeek",
    "Milvus", "FAISS", "Chroma", "Pinecone", "Weaviate", "Qdrant",
    "Gradio", "Streamlit", "FastAPI", "Ray", "Dask",
]

VERSION_PATTERN = re.compile(
    r"(?:version|v|v\.)?\s*(\d+\.\d+(?:\.\d+)?(?:[-.]?[a-zA-Z0-9]+)?)",
    re.IGNORECASE,
)


def extract_assets(text):
    """从描述中提取 AI 框架 + 版本号"""
    if not text:
        return {"frameworks": [], "versions": []}

    text_lower = text.lower()
    found = []
    for fw in AI_FRAMEWORKS:
        if fw.lower() in text_lower:
            found.append(fw)

    versions = list(dict.fromkeys(VERSION_PATTERN.findall(text)))[:10]

    return {
        "frameworks": list(dict.fromkeys(found)),
        "versions": versions,
    }


if __name__ == "__main__":
    samples = [
        "PyTorch 2.1.0 and Transformers 4.35.0 allow arbitrary code execution via pickle.",
        "A prompt injection in LangChain 0.0.350 bypasses safety filters in GPT-4.",
        "WordPress plugin WP Travel before 12.0.2 is vulnerable to SQL injection.",
    ]
    for s in samples:
        r = extract_assets(s)
        print(f"输入: {s[:60]}...")
        print(f"  框架: {r['frameworks']}")
        print(f"  版本: {r['versions']}")
        print()