import { Secret } from '../../src/types';
import { 
  parseSecretReference, 
  resolveSecretReferences, 
  normalizeKey 
} from '../../src/utils/secretReferencing';

describe('Secret Referencing Utils', () => {
  describe('parseSecretReference', () => {
    it('should parse local secret reference', () => {
      const result = parseSecretReference('${SECRET_KEY}');
      expect(result).toEqual({
        app: null,
        env: null,
        path: '/',
        key: 'SECRET_KEY'
      });
    });

    it('should parse local folder secret reference', () => {
      const result = parseSecretReference('${/path/to/SECRET_KEY}');
      expect(result).toEqual({
        app: null,
        env: null,
        path: '/path/to',
        key: 'SECRET_KEY'
      });
    });

    it('should parse cross-env secret reference', () => {
      const result = parseSecretReference('${prod.SECRET_KEY}');
      expect(result).toEqual({
        app: null,
        env: 'prod',
        path: '/',
        key: 'SECRET_KEY'
      });
    });

    it('should parse cross-env folder secret reference', () => {
      const result = parseSecretReference('${prod./path/to/SECRET_KEY}');
      expect(result).toEqual({
        app: null,
        env: 'prod',
        path: '/path/to',
        key: 'SECRET_KEY'
      });
    });

    it('should parse cross-app secret reference', () => {
      const result = parseSecretReference('${app-name::SECRET_KEY}');
      expect(result).toEqual({
        app: 'app-name',
        env: null,
        path: '/',
        key: 'SECRET_KEY'
      });
    });

    it('should parse cross-app folder secret reference', () => {
      const result = parseSecretReference('${app-name::/path/to/SECRET_KEY}');
      expect(result).toEqual({
        app: 'app-name',
        env: null,
        path: '/path/to',
        key: 'SECRET_KEY'
      });
    });

    it('should parse cross-app cross-env secret reference', () => {
      const result = parseSecretReference('${app-name::prod.SECRET_KEY}');
      expect(result).toEqual({
        app: 'app-name',
        env: 'prod',
        path: '/',
        key: 'SECRET_KEY'
      });
    });

    it('should parse cross-app cross-env folder secret reference', () => {
      const result = parseSecretReference('${app-name::prod./path/to/SECRET_KEY}');
      expect(result).toEqual({
        app: 'app-name',
        env: 'prod',
        path: '/path/to',
        key: 'SECRET_KEY'
      });
    });

    it('should handle invalid reference format', () => {
      expect(() => parseSecretReference('invalid')).toThrow('Invalid secret reference format');
    });
  });

  describe('normalizeKey', () => {
    it('should normalize key without app', () => {
      const result = normalizeKey('prod', '/path/to', 'SECRET_KEY');
      expect(result).toBe('prod:/path/to:SECRET_KEY');
    });

    it('should normalize key with app', () => {
      const result = normalizeKey('prod', '/path/to', 'SECRET_KEY', 'app-name');
      expect(result).toBe('app-name:prod:/path/to:SECRET_KEY');
    });

    it('should handle trailing slashes in path', () => {
      const result = normalizeKey('prod', '/path/to/', 'SECRET_KEY');
      expect(result).toBe('prod:/path/to:SECRET_KEY');
    });
  });

  describe('resolveSecretReferences', () => {
    const mockFetcher = jest.fn();
    const cache = new Map<string, string>();

    beforeEach(() => {
      mockFetcher.mockClear();
      cache.clear();
    });

    it('should resolve local secret reference', async () => {
      mockFetcher.mockResolvedValueOnce({
        value: 'secret-value',
        key: 'SECRET_KEY',
        environment: 'dev',
        path: '/',
        id: '1',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      const result = await resolveSecretReferences(
        '${SECRET_KEY}',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );

      expect(result).toBe('secret-value');
      expect(mockFetcher).toHaveBeenCalledWith('dev', '/', 'SECRET_KEY', null);
    });

    it('should resolve cross-env secret reference', async () => {
      mockFetcher.mockResolvedValueOnce({
        value: 'prod-secret',
        key: 'SECRET_KEY',
        environment: 'prod',
        path: '/',
        id: '1',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      const result = await resolveSecretReferences(
        '${prod.SECRET_KEY}',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );

      expect(result).toBe('prod-secret');
      expect(mockFetcher).toHaveBeenCalledWith('prod', '/', 'SECRET_KEY', null);
    });

    it('should resolve cross-app secret reference', async () => {
      mockFetcher.mockResolvedValueOnce({
        value: 'app-secret',
        key: 'SECRET_KEY',
        environment: 'dev',
        path: '/',
        id: '1',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      const result = await resolveSecretReferences(
        '${app-name::SECRET_KEY}',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );

      expect(result).toBe('app-secret');
      expect(mockFetcher).toHaveBeenCalledWith('dev', '/', 'SECRET_KEY', 'app-name');
    });

    it('should resolve nested secret references', async () => {
      // First level reference
      mockFetcher.mockResolvedValueOnce({
        value: '${NESTED_KEY}',
        key: 'SECRET_KEY',
        environment: 'dev',
        path: '/',
        id: '1',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      // Second level reference
      mockFetcher.mockResolvedValueOnce({
        value: 'final-value',
        key: 'NESTED_KEY',
        environment: 'dev',
        path: '/',
        id: '2',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      const result = await resolveSecretReferences(
        '${SECRET_KEY}',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );

      expect(result).toBe('final-value');
      expect(mockFetcher).toHaveBeenCalledTimes(2);
    });

    it('should detect circular references', async () => {
      // First level reference
      mockFetcher.mockResolvedValueOnce({
        value: '${CIRCULAR_KEY}',
        key: 'SECRET_KEY',
        environment: 'dev',
        path: '/',
        id: '1',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      // Circular reference
      mockFetcher.mockResolvedValueOnce({
        value: '${SECRET_KEY}',
        key: 'CIRCULAR_KEY',
        environment: 'dev',
        path: '/',
        id: '2',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      const result = await resolveSecretReferences(
        '${SECRET_KEY}',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );
      
      expect(result).toBe('${SECRET_KEY}');
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Circular reference detected'));
      consoleSpy.mockRestore();
    });

    it('should handle multiple references in a single value', async () => {
      mockFetcher
        .mockResolvedValueOnce({
          value: 'first-value',
          key: 'FIRST_KEY',
          environment: 'dev',
          path: '/',
          id: '1',
          comment: '',
          tags: [],
          keyDigest: '',
          createdAt: undefined,
          updatedAt: new Date().toISOString(),
          version: 1
        })
        .mockResolvedValueOnce({
          value: 'second-value',
          key: 'SECOND_KEY',
          environment: 'dev',
          path: '/',
          id: '2',
          comment: '',
          tags: [],
          keyDigest: '',
          createdAt: undefined,
          updatedAt: new Date().toISOString(),
          version: 1
        });

      const result = await resolveSecretReferences(
        '${FIRST_KEY}-${SECOND_KEY}',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );

      expect(result).toBe('first-value-second-value');
      expect(mockFetcher).toHaveBeenCalledTimes(2);
    });

    it('should handle folder paths correctly', async () => {
      mockFetcher.mockResolvedValueOnce({
        value: 'folder-secret',
        key: 'SECRET_KEY',
        environment: 'dev',
        path: '/path/to',
        id: '1',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      const result = await resolveSecretReferences(
        '${/path/to/SECRET_KEY}',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );

      expect(result).toBe('folder-secret');
      expect(mockFetcher).toHaveBeenCalledWith('dev', '/path/to', 'SECRET_KEY', null);
    });

    it('should handle mixed references with literals', async () => {
      mockFetcher.mockResolvedValueOnce({
        value: 'secret-value',
        key: 'SECRET_KEY',
        environment: 'dev',
        path: '/',
        id: '1',
        comment: '',
        tags: [],
        keyDigest: '',
        createdAt: undefined,
        updatedAt: new Date().toISOString(),
        version: 1
      });

      const result = await resolveSecretReferences(
        'prefix-${SECRET_KEY}-suffix',
        'dev',
        '/',
        mockFetcher,
        null,
        cache
      );

      expect(result).toBe('prefix-secret-value-suffix');
    });
  });
}); 