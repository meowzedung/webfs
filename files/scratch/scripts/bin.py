import numpy as np
from scipy.optimize import brentq

def solve_geometry_numerically(w, h, phi_deg):
    phi_rad = np.radians(phi_deg)

    D_fixed = np.array([-w, -h])
    B = np.array([0.0, 0.0])
    C_initial = np.array([0.0, -h])
    D_initial = np.array([-w, -h])

    def rotate_point(point, angle_deg):
        rad = np.radians(angle_deg)
        c, s = np.cos(rad), np.sin(rad)
        x_new = point[0] * c + point[1] * s
        y_new = -point[0] * s + point[1] * c
        return np.array([x_new, y_new])

    def angle_between(u, v):
        return np.arccos(
            np.clip(np.dot(u, v) / (np.linalg.norm(u) * np.linalg.norm(v)), -1.0, 1.0)
        )

    def alignment_error(theta_guess):
        C_prime = rotate_point(C_initial, theta_guess)
        D_prime = rotate_point(D_initial, theta_guess)

        vec_edge = D_prime - C_prime
        vec_line = D_fixed - C_prime

        return angle_between(vec_edge, vec_line) - phi_rad

    theta_solution = brentq(alignment_error, 1e-3, 179.0)

    C_prime = rotate_point(C_initial, theta_solution)
    vec_line = D_fixed - C_prime
    dist_to_D = np.linalg.norm(vec_line)
    unit_vec = vec_line / dist_to_D

    d_prime = C_prime + unit_vec * w
    ED_length = abs(D_fixed[1] - d_prime[1])

    return theta_solution, ED_length


w = float(input("Enter width w: "))
h = float(input("Enter height h: "))
phi_deg = float(input("Enter angle phi (degrees): "))

theta, ed = solve_geometry_numerically(w, h, phi_deg)

print(f"\nInputs: w={w}, h={h}, phi={phi_deg}°")
print("-" * 30)
print(f"Theta: {theta:.2f}°")
print(f"ED:    {ed:.2f}")
