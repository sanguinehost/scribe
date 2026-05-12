use super::cloud_embedding_client::CloudEmbeddingClient;
use super::mistralrs_adapter::MistralRsRigAdapter;
use rig::embeddings::{Embedding, EmbeddingError, EmbeddingModel};

#[derive(Clone)]
pub enum UnifiedEmbeddingModel {
    Cloud(CloudEmbeddingClient),
    Local(MistralRsRigAdapter),
}

impl UnifiedEmbeddingModel {
    pub fn ndims(&self) -> usize {
        match self {
            Self::Cloud(c) => c.ndims(),
            Self::Local(l) => l.ndims(),
        }
    }
}

impl EmbeddingModel for UnifiedEmbeddingModel {
    const MAX_DOCUMENTS: usize = 64;
    type Client = ();

    fn make(_client: &Self::Client, _model: impl Into<String>, _ndims: Option<usize>) -> Self {
        unimplemented!("UnifiedEmbeddingModel must be created via constructor")
    }

    fn ndims(&self) -> usize {
        match self {
            Self::Cloud(c) => c.ndims(),
            Self::Local(l) => l.ndims(),
        }
    }

    #[allow(refining_impl_trait)]
    fn embed_texts(
        &self,
        documents: impl IntoIterator<Item = String> + Send,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Embedding>, EmbeddingError>> + Send>,
    > {
        let documents: Vec<String> = documents.into_iter().collect();
        match self {
            Self::Cloud(c) => c.embed_texts(documents),
            Self::Local(l) => l.embed_texts(documents),
        }
    }
}
