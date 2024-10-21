export interface User {
  id: number;         // Identifiant unique de l'utilisateur
  username: string;  // Nom d'utilisateur
  email: string;     // Adresse e-mail de l'utilisateur
  password?: string; // Mot de passe de l'utilisateur (optionnel pour l'affichage)
  role: string;      // Rôle de l'utilisateur (par exemple, ADMIN ou USER)
}
