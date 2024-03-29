import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, tap } from 'rxjs';
import { StorageService } from './storage.service';

const AUTH_API = 'http://localhost:8080/api/auth/';

const httpOptions = {
  headers: new HttpHeaders({ 'Content-Type': 'application/json' })
};

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private isAuthenticated = new BehaviorSubject<boolean>(this.storageService.isLoggedIn());
  constructor(private http: HttpClient, private storageService: StorageService) {}

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
    return this.http.post(AUTH_API + 'signout', { }, httpOptions);
  }

  // logout(): Observable<any> {
  //   // Assuming the backend endpoint clears the session/cookie
  //   return this.http.post<any>(AUTH_API + 'signout', {}).pipe(
  //     tap(() => {
  //       this.storageService.clean();  // Clear local storage or session
  //       this.setAuthStatus(false);    // Update auth status
  //     })
  //   );
  // }
  

  refreshToken() {
    return this.http.post(AUTH_API + 'refreshtoken', { }, httpOptions);
  }
}
