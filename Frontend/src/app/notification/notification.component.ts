import { Component } from '@angular/core';
import { NotificationService } from '../services/notification.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-notification',
  templateUrl: './notification.component.html',
  styleUrls: ['./notification.component.scss']
})
export class NotificationComponent {

  constructor(private notificationService: NotificationService) { }

  // Méthode pour déclencher manuellement la notification de fin de contrat
  triggerContractNotification(): void {
    this.notificationService.triggerContractNotification().subscribe({
      next: () => this.showNotification('Les notifications ont été envoyées avec succès.'),
      error: err => console.error('Erreur lors de l\'envoi des notifications', err)
    });
  }

  // Affichage d'une notification avec SweetAlert
  private showNotification(message: string): void {
    Swal.fire({
      title: 'Notification',
      text: message,
      icon: 'info',
      confirmButtonText: 'OK'
    });
  }
}
