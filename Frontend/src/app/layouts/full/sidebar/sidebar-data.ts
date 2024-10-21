import { NavItem } from './nav-item/nav-item';

export const navItems: NavItem[] = [
  {
    navCap: 'Home',
  },
  {
    displayName: 'Dashboard',
    iconName: 'layout-dashboard',
    route: '/dashboard',
  },
 
  {
    navCap: 'Auth',
  },
  {
    displayName: 'Login',
    iconName: 'lock',
    route: '/authentication/login',
  },
  {
    displayName: 'Register',
    iconName: 'user-plus',
    route: '/authentication/register',
  },
  
  {
    navCap: 'Users',
  },
  {
    displayName: 'Table User',
    iconName: 'users',
    route: '/users',
  },
  {
    navCap: 'Company',
  },
  {
    displayName: 'Table Entreprise',
    iconName: 'building',
    route: '/entreprises',
  },
  {
    navCap: 'Contract',
  },
  {
    displayName: 'Table Contrat',
    iconName: 'file-contract',
    route: '/contrats',
  },
  {
    navCap: 'Documents',
  },
  {
    displayName: 'List documents',
    iconName: 'file-text',
    route: '/documents',
  },
  {
    navCap: 'Notifications',
  },
  {
    displayName: 'Notifications',
    iconName: 'bell', // Choisissez une icône appropriée pour les notifications
    route: '/notifications', // Route vers le composant de notification
  },
];
