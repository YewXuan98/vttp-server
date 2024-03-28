import { Component, OnInit } from '@angular/core';
import { UserService } from '../_services/user.service';
import { StorageService } from '../_services/storage.service';
import { EventBusService } from '../_shared/event-bus.service';
import { EventData } from '../_shared/event.class';

@Component({
  selector: 'app-board-user',
  templateUrl: './board-user.component.html',
  styleUrls: ['./board-user.component.css']
})
export class BoardUserComponent implements OnInit {
  content?: string;

  constructor(
    private userService: UserService,
    private storageService: StorageService,
    private eventBusService: EventBusService
  ) {}

  ngOnInit(): void {
    this.userService.getUserBoard().subscribe({
      next: data => {
        this.content = data;
      },
      error: err => {
        // ...

        if (err.status === 401 && this.storageService.isLoggedIn()) {
          this.eventBusService.emit(new EventData('logout', null));
        }
      }
    });
  }
}