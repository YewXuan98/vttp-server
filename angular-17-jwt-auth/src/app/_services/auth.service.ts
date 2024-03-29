import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, catchError, interval, Observable, tap, throwError } from 'rxjs';
import { StorageService } from './storage.service';
import { Router } from '@angular/router';
import { EventData } from '../_shared/event.class';
import { EventBusService } from '../_shared/event-bus.service';

const AUTH_API = 'http://localhost:8080/api/auth/';
const tokenCheckInterval = 3000; // Check every 60 seconds

const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json' }),
};

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private isAuthenticated = new BehaviorSubject<boolean>(
    this.storageService.isLoggedIn()
  );
  constructor(
    private http: HttpClient,
    private storageService: StorageService,
    private eventBusService: EventBusService,
    private router: Router
  ) {
    this.startTokenValidationCheck();
  }

  getAuthStatus(): Observable<boolean> {
    return this.isAuthenticated.asObservable();
  }

  setAuthStatus(status: boolean): void {
    this.isAuthenticated.next(status);
  }

  login(username: string, password: string): Observable<any> {
    return this.http.post(
      AUTH_API + 'signin',
      {
        username,
        password,
      },
      httpOptions
    );
  }

  register(username: string, email: string, password: string): Observable<any> {
    return this.http.post(
      AUTH_API + 'signup',
      {
        username,
        email,
        password,
      },
      httpOptions
    );
  }

  logout(): Observable<any> {
    return this.http.post(AUTH_API + 'signout', {}, httpOptions);
  }

  refreshToken() {
    const refreshToken = this.storageService.getToken();  
    return this.http.post(AUTH_API + 'refreshtoken', { token: refreshToken}, httpOptions).pipe(
      tap(() => {
        this.setAuthStatus(true);
      }),
      catchError((error) => {
        this.logout(); // Logout if refresh token fails
        this.eventBusService.emit(new EventData('logout', null));
        return throwError(() => new Error('Failed to refresh token'));
      })
    );
  }

  private startTokenValidationCheck(): void {
    interval(tokenCheckInterval).subscribe(() => {
      if (!this.storageService.isLoggedIn()) {
        this.logout();
        return;
      }

      const isTokenExpired = this.storageService.isTokenExpired(); // Implement this method in storageService
      if (isTokenExpired) {
        this.refreshToken().subscribe();
      }
    });
  }
}
