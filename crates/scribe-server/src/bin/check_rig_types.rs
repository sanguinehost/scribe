use rig::embeddings::Embedding;

fn main() {
    let e = Embedding {
        document: "test".to_string(),
        vec: vec![0.0],
    };
    println!("Embedding: {:?}", e.document);
}
