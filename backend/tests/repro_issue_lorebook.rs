#![cfg(feature = "postgres-backend")]
#[cfg(test)]
mod tests {
    use scribe_backend::services::character_parser::{
        parse_character_card_png, ParsedCharacterCard,
    };

    #[test]
    fn test_parse_v2_with_world_info() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        // Read the PNG file directly
        let png_path =
            "/home/socol/Downloads/main_my-hero-academia-rpg-overhaul-5ca1a8ee2ac5_spec_v2.png";
        let png_data = std::fs::read(png_path).expect("Failed to read PNG file");

        let parsed = parse_character_card_png(&png_data);

        match parsed {
            Ok(ParsedCharacterCard::V2Fallback(data)) => {
                println!("Parsed as V2Fallback");
                assert!(
                    data.character_book.is_some(),
                    "character_book should be Some"
                );
                let book = data.character_book.unwrap();
                println!("Character book found: {:?}", book);
            }
            Ok(ParsedCharacterCard::V3(card)) => {
                println!("Parsed as V3");
                assert!(
                    card.data.character_book.is_some(),
                    "character_book should be Some"
                );
                let book = card.data.character_book.unwrap();
                println!("Character book found: {:?}", book);
            }
            Err(e) => {
                panic!("Failed to parse: {:?}", e);
            }
        }
    }
}
