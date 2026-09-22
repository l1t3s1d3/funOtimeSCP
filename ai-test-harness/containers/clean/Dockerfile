# Clean reproduction of the TEI container image.
# Adjust the base image and model path to match the target deployment.
FROM ghcr.io/huggingface/text-embeddings-inference:cpu-latest

# Copy in the clean model weights
COPY models/ /data/

# Default entrypoint from the TEI image
# Adjust --model-id if the target uses a different path
CMD ["--model-id", "/data"]
