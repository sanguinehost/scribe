// backend/src/models/spatial.rs
//
// Enhanced spatial system with flexible hierarchy and containment relationships
// Replaces rigid 3-tier SpatialScale with flexible SpatialType system

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use uuid::Uuid;

/// Flexible spatial type system supporting arbitrary containment relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpatialType {
    // Cosmic Scale
    Universe,
    Galaxy,
    GalaxyCluster,
    Nebula,
    StarSystem,
    Star,
    Planet,
    Moon,
    Asteroid,
    AsteroidBelt,
    Comet,
    SpaceStation,
    
    // Vehicles & Vessels
    Spaceship,
    Starship,
    Shuttle,
    Fighter,
    Freighter,
    Ship,
    Airship,
    Aircraft,
    Vehicle,
    
    // Geographic Scale
    Continent,
    Ocean,
    Sea,
    MountainRange,
    Desert,
    Forest,
    Jungle,
    Tundra,
    Grassland,
    Swamp,
    Marsh,
    River,
    Lake,
    Island,
    Peninsula,
    Valley,
    Canyon,
    Cave,
    Cavern,
    
    // Political Scale
    Empire,
    Kingdom,
    Republic,
    Province,
    State,
    County,
    City,
    Town,
    Village,
    District,
    Neighborhood,
    
    // Structural Scale
    Fortress,
    Castle,
    Palace,
    Temple,
    Tower,
    Building,
    House,
    Inn,
    Tavern,
    Shop,
    Market,
    Bridge,
    Port,
    Dock,
    Warehouse,
    Floor,
    Room,
    Chamber,
    Hall,
    Corridor,
    Courtyard,
    Garden,
    Basement,
    Attic,
    Deck,
    Cabin,
    Cockpit,
    CargoHold,
    EngineeringBay,
    
    // Intimate Scale
    Area,
    Furniture,
    Container,
    Compartment,
    Locker,
    Chest,
    Shelf,
    Table,
    Bed,
    Chair,
    
    // Flexible extension point
    Custom(String),
}

impl SpatialType {
    /// Check if this spatial type can logically contain another
    pub fn can_contain(&self, other: &SpatialType) -> bool {
        use SpatialType::*;
        
        match (self, other) {
            // Universe can contain galaxy clusters and galaxies
            (Universe, GalaxyCluster) | (Universe, Galaxy) => true,
            
            // Galaxy clusters can contain galaxies
            (GalaxyCluster, Galaxy) => true,
            
            // Galaxies can contain star systems and nebulae
            (Galaxy, StarSystem) | (Galaxy, Nebula) => true,
            
            // Star systems can contain stars, planets, moons, asteroids, etc.
            (StarSystem, Star) | (StarSystem, Planet) | (StarSystem, Moon) | 
            (StarSystem, Asteroid) | (StarSystem, AsteroidBelt) | (StarSystem, Comet) |
            (StarSystem, SpaceStation) => true,
            
            // Asteroid belts can contain individual asteroids
            (AsteroidBelt, Asteroid) => true,
            
            // Planets can contain moons in orbit
            (Planet, Moon) | (Planet, SpaceStation) => true,
            
            // Space stations can contain ships and internal structures
            (SpaceStation, Spaceship) | (SpaceStation, Starship) | (SpaceStation, Shuttle) |
            (SpaceStation, Fighter) | (SpaceStation, Freighter) | (SpaceStation, Deck) |
            (SpaceStation, Corridor) | (SpaceStation, Room) | (SpaceStation, Dock) => true,
            
            // Ships can contain decks, rooms, and cargo
            (Spaceship, Deck) | (Spaceship, Cabin) | (Spaceship, Cockpit) |
            (Spaceship, CargoHold) | (Spaceship, EngineeringBay) | (Spaceship, Corridor) |
            (Starship, Deck) | (Starship, Cabin) | (Starship, Cockpit) |
            (Starship, CargoHold) | (Starship, EngineeringBay) | (Starship, Corridor) |
            (Freighter, CargoHold) | (Freighter, Cabin) | (Freighter, Cockpit) => true,
            
            // Planets can contain geographic and political entities
            (Planet, Continent) | (Planet, Ocean) | (Planet, Sea) | 
            (Planet, Empire) | (Planet, Kingdom) | (Planet, Republic) => true,
            
            // Oceans can contain seas and islands
            (Ocean, Sea) | (Ocean, Island) => true,
            
            // Continents can contain various geographic features
            (Continent, MountainRange) | (Continent, Desert) | (Continent, Forest) |
            (Continent, Jungle) | (Continent, Tundra) | (Continent, Grassland) |
            (Continent, Swamp) | (Continent, Marsh) | (Continent, Valley) |
            (Continent, Canyon) | (Continent, Peninsula) | (Continent, River) | 
            (Continent, Lake) | (Continent, Kingdom) | (Continent, Empire) | 
            (Continent, Republic) => true,
            
            // Mountain ranges can contain fortresses, temples, caves, etc.
            (MountainRange, Fortress) | (MountainRange, Temple) | 
            (MountainRange, Castle) | (MountainRange, Tower) |
            (MountainRange, Cave) | (MountainRange, Cavern) => true,
            
            // Valleys and canyons can contain settlements
            (Valley, Village) | (Valley, Town) | (Canyon, Cave) => true,
            
            // Caves can contain caverns
            (Cave, Cavern) => true,
            
            // Political entities hierarchy
            (Empire, Kingdom) | (Empire, Province) | (Kingdom, Province) |
            (Province, County) | (County, City) | (Province, City) |
            (City, District) | (District, Neighborhood) => true,
            
            // Cities and towns can contain structures
            (City, Building) | (City, Castle) | (City, Temple) | (City, Palace) |
            (City, Market) | (City, Port) | (City, Bridge) | (City, Inn) |
            (City, Tavern) | (City, Shop) | (City, House) | (City, Warehouse) |
            (Town, Building) | (Town, Inn) | (Town, Tavern) | (Town, Shop) |
            (Town, Market) | (Town, House) | (Village, Building) | 
            (Village, Inn) | (Village, House) => true,
            
            // Ports can contain docks and warehouses
            (Port, Dock) | (Port, Warehouse) | (Port, Ship) => true,
            
            // Structural hierarchy
            (Castle, Tower) | (Castle, Courtyard) | (Castle, Hall) | (Castle, Chamber) |
            (Palace, Hall) | (Palace, Chamber) | (Palace, Courtyard) | (Palace, Garden) |
            (Building, Floor) | (Building, Basement) | (Building, Attic) |
            (House, Floor) | (House, Room) | (House, Basement) | (House, Attic) |
            (Inn, Floor) | (Inn, Room) | (Tavern, Room) | (Shop, Room) |
            (Floor, Room) | (Floor, Hall) | (Floor, Chamber) | (Floor, Corridor) |
            (Room, Area) | (Room, Furniture) | (Area, Furniture) |
            (Chamber, Furniture) | (Hall, Furniture) | (Cabin, Furniture) => true,
            
            // Furniture and container hierarchy
            (Furniture, Container) | (Table, Container) | (Shelf, Container) |
            (Chest, Compartment) | (Locker, Compartment) | (CargoHold, Container) |
            (Room, Table) | (Room, Bed) | (Room, Chair) | (Room, Chest) |
            (Room, Shelf) | (Room, Locker) => true,
            
            // Custom types - allow any containment (validated elsewhere)
            (Custom(_), _) | (_, Custom(_)) => true,
            
            // Default: types at similar scale can contain each other
            _ => false,
        }
    }
    
    /// Get a human-readable description of this spatial type
    pub fn description(&self) -> &str {
        use SpatialType::*;
        
        match self {
            Universe => "The entirety of existence",
            Galaxy => "A massive collection of star systems",
            GalaxyCluster => "A gravitationally bound group of galaxies",
            Nebula => "A vast cloud of gas and dust in space",
            StarSystem => "A star and its orbiting bodies",
            Star => "A luminous celestial body",
            Planet => "A celestial body orbiting a star",
            Moon => "A natural satellite orbiting a planet",
            Asteroid => "A small rocky body orbiting a star",
            AsteroidBelt => "A region containing many asteroids",
            Comet => "An icy body that releases gas when near a star",
            SpaceStation => "An artificial structure in space",
            Spaceship => "A vehicle designed for space travel",
            Starship => "A large vessel for interstellar travel",
            Shuttle => "A small spacecraft for short trips",
            Fighter => "A small combat spacecraft",
            Freighter => "A cargo transport spacecraft",
            Ship => "A water-based vessel",
            Airship => "A lighter-than-air flying vessel",
            Aircraft => "A powered flying vehicle",
            Vehicle => "A land-based transport",
            Continent => "A large landmass",
            Ocean => "A vast body of salt water",
            Sea => "A large body of salt water, smaller than an ocean",
            MountainRange => "A series of connected mountains",
            Desert => "An arid region with little vegetation",
            Forest => "A dense collection of trees",
            Jungle => "A tropical forest with dense vegetation",
            Tundra => "A cold, treeless region",
            Grassland => "An area dominated by grasses",
            Swamp => "A wetland with trees and standing water",
            Marsh => "A wetland dominated by grasses",
            River => "A flowing body of water",
            Lake => "A body of water surrounded by land",
            Island => "Land surrounded by water",
            Peninsula => "Land projecting into water",
            Valley => "A low area between hills or mountains",
            Canyon => "A deep gorge with steep sides",
            Cave => "A natural underground space",
            Cavern => "A large cave or chamber",
            Empire => "A group of nations under single rule",
            Kingdom => "A realm ruled by a monarch",
            Republic => "A state with elected leadership",
            Province => "An administrative division of a country",
            State => "A territorial division with local government",
            County => "An administrative district",
            City => "A large, populated urban area",
            Town => "A populated area smaller than a city",
            Village => "A small community",
            District => "A division within a city",
            Neighborhood => "A local community within a district",
            Fortress => "A military stronghold",
            Castle => "A fortified residence",
            Palace => "A grand residence",
            Temple => "A place of worship",
            Tower => "A tall, narrow structure",
            Building => "A constructed structure",
            House => "A residential building",
            Inn => "A building providing lodging",
            Tavern => "A place serving food and drink",
            Shop => "A place of commerce",
            Market => "An area for trading goods",
            Bridge => "A structure spanning a gap",
            Port => "A harbor for ships",
            Dock => "A platform for loading ships",
            Warehouse => "A building for storing goods",
            Floor => "A level within a building",
            Room => "An enclosed space within a building",
            Chamber => "A private or formal room",
            Hall => "A large room or passageway",
            Corridor => "A passageway connecting rooms",
            Courtyard => "An enclosed outdoor area",
            Garden => "A cultivated outdoor space",
            Basement => "An underground floor",
            Attic => "A space under the roof",
            Deck => "A platform on a ship or building",
            Cabin => "A small room on a ship",
            Cockpit => "A control room for pilots",
            CargoHold => "Storage area in a ship",
            EngineeringBay => "Technical workspace on a ship",
            Area => "A defined space",
            Furniture => "Movable objects in a room",
            Container => "An object that holds items",
            Compartment => "A separated section within a container",
            Locker => "A secure storage unit",
            Chest => "A large storage box",
            Shelf => "A horizontal surface for storage",
            Table => "A flat surface with legs",
            Bed => "Furniture for sleeping",
            Chair => "Furniture for sitting",
            Custom(name) => name,
        }
    }
}

/// Enhanced spatial component with flexible containment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedSpatialComponent {
    /// The type of spatial entity this is
    pub spatial_type: SpatialType,
    
    /// UUID of the entity that contains this one (if any)
    pub contained_by: Option<Uuid>,
    
    /// UUIDs of entities contained within this one
    pub contains: Vec<Uuid>,
    
    /// Position relative to parent container
    pub relative_position: Option<RelativePosition>,
    
    /// Absolute position in world coordinates (if applicable)
    pub absolute_position: Option<AbsolutePosition>,
    
    /// Extensible metadata for spatial properties
    pub metadata: HashMap<String, JsonValue>,
}

/// Position relative to a container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelativePosition {
    /// X coordinate relative to container's origin
    pub x: f64,
    /// Y coordinate relative to container's origin
    pub y: f64,
    /// Z coordinate relative to container's origin
    pub z: f64,
    /// Optional orientation
    pub rotation: Option<Rotation>,
}

/// Absolute position in world space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbsolutePosition {
    /// Latitude (for planetary scale)
    pub latitude: Option<f64>,
    /// Longitude (for planetary scale)
    pub longitude: Option<f64>,
    /// Altitude/elevation
    pub altitude: Option<f64>,
    /// Cartesian coordinates (for space/abstract positions)
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub z: Option<f64>,
}

/// Rotation/orientation in 3D space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rotation {
    pub pitch: f64,
    pub yaw: f64,
    pub roll: f64,
}

impl EnhancedSpatialComponent {
    /// Create a new spatial component
    pub fn new(spatial_type: SpatialType) -> Self {
        Self {
            spatial_type,
            contained_by: None,
            contains: Vec::new(),
            relative_position: None,
            absolute_position: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Add an entity to this container
    pub fn add_contained_entity(&mut self, entity_id: Uuid) {
        if !self.contains.contains(&entity_id) {
            self.contains.push(entity_id);
        }
    }
    
    /// Remove an entity from this container
    pub fn remove_contained_entity(&mut self, entity_id: &Uuid) {
        self.contains.retain(|id| id != entity_id);
    }
    
    /// Set this entity's container
    pub fn set_container(&mut self, container_id: Option<Uuid>) {
        self.contained_by = container_id;
    }
    
    /// Add metadata
    pub fn add_metadata(&mut self, key: String, value: JsonValue) {
        self.metadata.insert(key, value);
    }
}

// Component trait implementation
use crate::models::ecs::Component;

impl Component for EnhancedSpatialComponent {
    fn component_type() -> &'static str {
        "EnhancedSpatial"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_spatial_type_containment() {
        // Mountain range can contain fortress
        assert!(SpatialType::MountainRange.can_contain(&SpatialType::Fortress));
        
        // City can contain buildings
        assert!(SpatialType::City.can_contain(&SpatialType::Building));
        
        // Room cannot contain city
        assert!(!SpatialType::Room.can_contain(&SpatialType::City));
        
        // Custom types allow any containment
        assert!(SpatialType::Custom("Void".to_string()).can_contain(&SpatialType::Galaxy));
    }
    
    #[test]
    fn test_enhanced_spatial_component() {
        let mut fortress = EnhancedSpatialComponent::new(SpatialType::Fortress);
        let tower_id = Uuid::new_v4();
        
        // Test adding contained entities
        fortress.add_contained_entity(tower_id);
        assert_eq!(fortress.contains.len(), 1);
        assert!(fortress.contains.contains(&tower_id));
        
        // Test removing entities
        fortress.remove_contained_entity(&tower_id);
        assert_eq!(fortress.contains.len(), 0);
        
        // Test metadata
        fortress.add_metadata("defensive_rating".to_string(), serde_json::json!(8.5));
        assert_eq!(fortress.metadata.get("defensive_rating"), Some(&serde_json::json!(8.5)));
    }
}