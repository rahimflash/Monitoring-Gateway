-- Active: 1678731090110@@127.0.0.1@3306@flash
USE `flash`;

--
-- Table structure for table `admin`
--

DROP TABLE IF EXISTS `admin`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `admin` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password` varchar(128) NOT NULL,
  `Fname` varchar(35) NOT NULL,
  `Lname` varchar(35) NOT NULL,
  `phoneNumber` varchar(13) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `admin`
--

LOCK TABLES `admin` WRITE;
/*!40000 ALTER TABLE `admin` DISABLE KEYS */;
INSERT INTO `admin` VALUES
(2, 'twumgilbert7@gmail.com', '12345678','Gilbert', 'Twum',  '0245453642');

/*!40000 ALTER TABLE `admin` ENABLE KEYS */;
UNLOCK TABLES;